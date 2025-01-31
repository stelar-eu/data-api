import logging
import logging.config


def configure():
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,  # This is CRAP
            "formatters": {
                "standard": {
                    "format": "[%(asctime)s] %(name)5s - %(levelname)-5.5s - %(message)s",
                    "datefmt": "%y/%m/%d %H:%M:%S",
                },
                "simple": {"format": "%(name)s:%(levelname)s:%(message)s"},
                # werkzeug has its own logging with enough info, so...
                "werkzeug": {"format": "%(message)s"},
            },
            "handlers": {
                "cstderr": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "stream": "ext://sys.stderr",
                },
                "debugging": {
                    "class": "logging.StreamHandler",
                    "level": "DEBUG",
                    "formatter": "simple",
                    "stream": "ext://sys.stderr",
                },
                "wz": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "werkzeug",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "httpx": {"level": "WARNING", "propagate": False},
                "cutils": {"level": "DEBUG"},
                "rest_catalog": {"level": "DEBUG"},
                "data_api": {"level": "DEBUG"},
                "werkzeug": {"handlers": ["wz"], "propagate": False},
                "route": {"level": "DEBUG"},
            },
            "root": {
                "level": "DEBUG",
                "handlers": ["cstderr"],
            },
        }
    )
