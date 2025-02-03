import logging

import psycopg2
from flask import current_app
from psycopg2.pool import ThreadedConnectionPool

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


def initialize_db_pool(config):
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


def execSql(sql, vars=None):
    """Opens a connection to a PostgreSQL database and executes the given SQL command.

    Args:
        sql (String): The SQL command with variables to be executed in the database.
        vars (List): The values to use per variable in the SQL command.

    Returns:
        A JSON with the retrieved query results for SELECT commands; a JSON with the final execution status (True/False) for INSERT/UPDATE/DELETE commands.
    """

    config = current_app.config["settings"]

    data = None
    try:
        conn = mdb_pool.getconn()

        with conn.cursor() as cur:
            # Execute the SQL statement
            cur.execute(sql, vars)

            # Handle the response
            desc = cur.description

            if desc:  # SELECT commands
                column_names = [col[0] for col in desc]
                data = [dict(zip(column_names, row)) for row in cur.fetchall()]
            else:  # INSERT, UPDATE commands
                data = {}
                # obtain the inserted rows
                if cur.rowcount > 0:
                    data["status"] = True
                else:
                    data["status"] = False

            # Commit the changes to the database
            conn.commit()

        mdb_pool.putconn(conn)  # Return the connection to the pool
    except (Exception, psycopg2.DatabaseError) as error:
        logger.exception("Error in executing SQL command", sql)
        conn.putconn(close=True)  # Close this connection, just in case...
        raise
    return data


def execSql_old(sql, vars=None):
    """Opens a connection to a PostgreSQL database and executes the given SQL command.

    Args:
        sql (String): The SQL command with variables to be executed in the database.
        vars (List): The values to use per variable in the SQL command.

    Returns:
        A JSON with the retrieved query results for SELECT commands; a JSON with the final execution status (True/False) for INSERT/UPDATE/DELETE commands.
    """

    config = current_app.config["settings"]

    data = None
    try:
        with psycopg2.connect(
            dbname=config["dbname"],
            user=config["dbuser"],
            password=config["dbpass"],
            host=config["dbhost"],
            port=config["dbport"],
        ) as conn:
            with conn.cursor() as cur:
                # Execute the SQL statement
                cur.execute(sql, vars)

                # Handle the response
                desc = cur.description

                if desc:  # SELECT commands
                    column_names = [col[0] for col in desc]
                    data = [dict(zip(column_names, row)) for row in cur.fetchall()]
                else:  # INSERT, UPDATE commands
                    data = {}
                    # obtain the inserted rows
                    if cur.rowcount > 0:
                        data["status"] = True
                    else:
                        data["status"] = False

                # Commit the changes to the database
                conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        logger.exception("Error in executing SQL command", sql)
        raise
    finally:
        return data
