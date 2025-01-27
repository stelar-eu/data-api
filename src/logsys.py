import logging
import logging.config


def configure():
    logging.config.dictConfig(
        {
            "version": 1,
            "loggers": {
                "httpx": {"level": "WARNING", "propagate": False},
                "cutils": {"level": "DEBUG"},
            },
        }
    )
