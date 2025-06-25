import logging
import logging.config
import os

_override = os.getenv("FLASK_DEBUG", "false").lower() in ["true", "1", "yes"]


def override_level(level: str):
    global _override
    if _override:
        return "DEBUG"
    return level


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
                    "level": override_level("INFO"),
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
            "root": {
                "level": override_level("INFO"),
                "handlers": ["cstderr"],
            },
            "loggers": {
                "httpx": {"level": override_level("WARNING"), "propagate": False},
                "urllib3": {"level": override_level("WARNING"), "propagate": False},
                "werkzeug": {"handlers": ["wz"], "propagate": False},
                "cutils": {"level": override_level("WARNING")},
                "entity": {"level": override_level("WARNING")},
                "data_api": {"level": override_level("WARNING")},
                "authz_module": {"level": "DEBUG"},
                "execution.job": {"level": override_level("WARNING")},
                "routes": {"level": override_level("WARNING")},
                "routes.generic": {"level": override_level("WARNING")},
                "routes.catalog": {"level": override_level("WARNING")},
            },
        }
    )
