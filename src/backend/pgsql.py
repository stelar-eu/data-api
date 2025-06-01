import logging
from contextlib import contextmanager

from flask import g
from psycopg2.extensions import TRANSACTION_STATUS_IDLE
from psycopg2.pool import ThreadedConnectionPool

from exceptions import BackendError

logger = logging.getLogger(__name__)


class MdbPool:
    def __init__(self, minconn=1, maxconn=10):
        self.pool = None
        self.minconn = minconn
        self.maxconn = maxconn

    def init(self, dbname, user, password, host, port, minconn=None, maxconn=None):
        self.dbname = dbname
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        minconn = minconn or self.minconn
        maxconn = maxconn or self.maxconn
        self.pool = ThreadedConnectionPool(
            minconn=minconn,
            maxconn=maxconn,
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port,
        )

    def getconn(self):
        return self.pool.getconn()

    def putconn(self, conn):
        self.pool.putconn(conn)

    def closeall(self):
        self.pool.closeall()


mdb_pool = MdbPool()


def get_mdb_pool():
    """Returns the database connection pool."""
    global mdb_pool
    return mdb_pool


def initialize_mdb_pool(config):
    """Initializes the database connection pool."""
    # config = current_app.config["settings"]

    mdb_pool.init(
        minconn=1,
        maxconn=10,
        dbname=config["dbname"],
        user=config["dbuser"],
        password=config["dbpass"],
        host=config["dbhost"],
        port=config["dbport"],
    )


def get_dbconn():
    """Returns a connection to the database.

    The connection is retrieved from the connection pool and is saved in the
    application context 'flask.g' to be reused in the same request.
    Calling this function multiple times in the same request will return the
    same connection.
    """

    if "dbconn" not in g:
        g.dbconn = mdb_pool.getconn()
    return g.dbconn


@contextmanager
def transaction():
    """Context manager to handle transactions.

    Starts a transaction if none is in progress, commits if no exception,
    rolls back otherwise.

    Supports nesting by only committing/rolling back outermost transaction.
    """
    conn = get_dbconn()

    try:
        # If idle, start a transaction
        if conn.info.transaction_status == TRANSACTION_STATUS_IDLE:
            with conn.cursor() as cur:
                cur.execute("BEGIN")

            # Mark that we started the transaction and should commit/rollback
            is_outermost = True
        else:
            # Already in a transaction (nested)
            is_outermost = False

        yield conn

        # Commit only if outermost transaction
        if is_outermost:
            conn.commit()

    except Exception:
        # Rollback only if outermost transaction
        if is_outermost:
            conn.rollback()
        raise


def execSql(sql, vars=None):
    """Opens a connection to a PostgreSQL database and executes the given SQL command.

    Args:
        sql (String): The SQL command with variables to be executed in the database.
        vars (List): The values to use per variable in the SQL command.

    Returns:
        A JSON with the retrieved query results for SELECT commands; a JSON with the final execution status (True/False)
        for INSERT/UPDATE/DELETE commands.
    """

    data = None
    try:
        conn = get_dbconn()

        if conn.info.transaction_status == TRANSACTION_STATUS_IDLE:
            # Not in a transaction, commit as needed
            with conn:
                data = execSqlTx(conn, sql, vars)
        else:
            # In a transaction, do not commit here...
            data = execSqlTx(conn, sql, vars)

    except Exception:
        logger.exception("Error in executing SQL command", sql, vars)
        raise BackendError(
            "Error in executing SQL command", details={"sql": sql, "vars": vars}
        )
    return data


def execSqlTx(conn, sql, vars=None):
    """Executes the given SQL command in the given connection.

    The connection is expected to be in a transaction. This function does not commit the transaction.

    Args:
        conn (Connection): The connection to the database.
        sql (String): The SQL command with variables to be executed in the database.
        vars (List): The values to use per variable in the SQL command.

    Returns:
        For SELECT commands, a list of the retrieved tuples converted to dict.
        For INSERT/UPDATE/DELETE commandsa, a dict `{"status": s}` with s the execution status (True/False),
            indicating whether the command affected at least one tuple (i.e., rowcount > 0).

    """

    data = None
    with conn.cursor() as cur:
        # Execute the SQL statement
        try:
            cur.execute(sql, vars)
        except Exception:
            logger.exception("Error in executing SQL command", sql)
            raise

        # Handle the response
        desc = cur.description

        if desc:
            # SELECT commands
            column_names = [col[0] for col in desc]
            data = [dict(zip(column_names, row)) for row in cur.fetchall()]
        else:
            # INSERT, UPDATE commands
            data = {"status": cur.rowcount > 0}

    return data
