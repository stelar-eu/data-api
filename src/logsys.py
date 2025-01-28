import logging
import logging.config


def configure():
    logging.config.dictConfig(
        {
            "version": 1,
            "loggers": {
                # Root logger
                "": {"level": "DEBUG"},
                # Custom loggers
                "httpx": {"level": "WARNING", "propagate": False},
                "cutils": {"level": "DEBUG"},
                "rest_catalog": {"level": "DEBUG"},
            },
        }
    )
