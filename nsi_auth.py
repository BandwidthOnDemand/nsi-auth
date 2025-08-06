#  Copyright 2025 SURF.
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""Verify DN from HTTP header against list of allowed DN's."""

from logging.config import dictConfig

from flask import Flask, request
from pydantic import BaseModel, FilePath
from pydantic_settings import BaseSettings
from watchdog.events import DirModifiedEvent, FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer


#
# Authorization application
#
class Settings(BaseSettings):
    """Application settings."""

    allowed_client_subject_dn_path: FilePath = FilePath("/config/allowed_client_dn.txt")
    ssl_client_subject_dn_header: str = "ssl-client-subject-dn"


class State(BaseModel):
    """Application state."""

    allowed_client_subject_dn: list[str] = []


def init_app() -> Flask:
    """Initialize Flask app."""
    dictConfig(
        {
            "version": 1,
            "formatters": {
                "default": {
                    "format": "[%(asctime)s] [%(module)s] [%(levelname)s] %(message)s",
                }
            },
            "handlers": {
                "wsgi": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                    "formatter": "default",
                }
            },
            "root": {"level": "INFO", "handlers": ["wsgi"]},
            "disable_existing_loggers": False,
        }
    )
    app = Flask(__name__)
    app.logger.setLevel("DEBUG")

    return app


settings = Settings()
state = State()
app = init_app()


@app.route("/validate", methods=["GET"])
def validate() -> tuple[str, int]:
    """Verify the DN from the packet header against the list of allowed DN."""
    if not (dn := request.headers.get(settings.ssl_client_subject_dn_header)):
        app.logger.warning(f"no {settings.ssl_client_subject_dn_header} header on HTTP request")
        return "Forbidden", 403
    if dn not in state.allowed_client_subject_dn:
        app.logger.info(f"deny {dn}")
        return "Forbidden", 403
    app.logger.info(f"allow {dn}")
    return "OK", 200


#
# Load DN from file plus watchdog for auto reload.
#
class FileChangeHandler(FileSystemEventHandler):
    """On filesystem event, call load_allowed_client_dn() when `filepath` is modified."""

    def __init__(self, filepath: FilePath) -> None:
        """Set the filepath of the file to watch."""
        self.filepath = filepath.resolve()
        load_allowed_client_dn(self.filepath)
        app.logger.info(f"watch {self.filepath} for changes")

    def on_modified(self, event: DirModifiedEvent | FileModifiedEvent) -> None:
        """Call load_allowed_client_dn() when `filepath` is modified."""
        if FilePath(str(event.src_path)).resolve() == self.filepath:
            load_allowed_client_dn(self.filepath)


def load_allowed_client_dn(filepath: FilePath) -> None:
    """Load list of allowed client DN from file."""
    try:
        with filepath.open("r") as f:
            new_allowed_client_subject_dn = [line.strip() for line in f if line.strip()]
    except Exception as e:
        app.logger.error(f"cannot load allowed client DN from {filepath}: {e!s}")
    else:
        if state.allowed_client_subject_dn != new_allowed_client_subject_dn:
            state.allowed_client_subject_dn = new_allowed_client_subject_dn
            app.logger.info(f"load {len(new_allowed_client_subject_dn)} DN from {filepath}")


def watch_file(file_to_watch: FilePath) -> None:
    """Setup watchdog to watch directory that the file resides in and call handler on change."""
    observer = Observer()
    observer.schedule(FileChangeHandler(file_to_watch), path=str(file_to_watch.parent), recursive=False)
    observer.start()


watch_file(settings.allowed_client_subject_dn_path)
