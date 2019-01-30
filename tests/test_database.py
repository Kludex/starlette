import os

import pytest
import sqlalchemy

from starlette.applications import Starlette
from starlette.database import transaction
from starlette.datastructures import CommaSeparatedStrings, DatabaseURL
from starlette.middleware.database import DatabaseMiddleware
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

try:
    DATABASE_URLS = CommaSeparatedStrings(os.environ["STARLETTE_TEST_DATABASES"])
except KeyError:  # pragma: no cover
    pytest.skip("STARLETTE_TEST_DATABASES is not set", allow_module_level=True)

metadata = sqlalchemy.MetaData()

notes = sqlalchemy.Table(
    "notes",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("text", sqlalchemy.String(length=100)),
    sqlalchemy.Column("completed", sqlalchemy.Boolean),
)


@pytest.fixture(autouse=True, scope="module")
def create_test_databases():
    engines = {}
    for url in DATABASE_URLS:
        db_url = DatabaseURL(url)
        if db_url.dialect == "mysql":
            #  Use the 'pymysql' driver for creating the database & tables.
            url = str(db_url.replace(scheme="mysql+pymysql"))
            db_name = db_url.database
            db_url = db_url.replace(scheme="mysql+pymysql", database="")
            engine = sqlalchemy.create_engine(str(db_url))
            engine.execute("CREATE DATABASE IF NOT EXISTS " + db_name)

        engines[url] = sqlalchemy.create_engine(url)
        metadata.create_all(engines[url])

    yield

    for engine in engines.values():
        engine.execute("DROP TABLE notes")


def get_app(database_url):
    app = Starlette()
    app.add_middleware(
        DatabaseMiddleware, database_url=database_url, rollback_on_shutdown=True
    )

    @app.route("/notes", methods=["GET"])
    async def list_notes(request):
        query = notes.select()
        results = await request.database.fetchall(query)
        content = [
            {"text": result["text"], "completed": result["completed"]}
            for result in results
        ]
        return JSONResponse(content)

    @app.route("/notes", methods=["POST"])
    @transaction
    async def add_note(request):
        data = await request.json()
        query = notes.insert().values(text=data["text"], completed=data["completed"])
        await request.database.execute(query)
        if "raise_exc" in request.query_params:
            raise RuntimeError()
        return JSONResponse({"text": data["text"], "completed": data["completed"]})

    @app.route("/notes/bulk_create", methods=["POST"])
    async def bulk_create_notes(request):
        data = await request.json()
        query = notes.insert()
        await request.database.executemany(query, data)
        return JSONResponse({"notes": data})

    @app.route("/notes/{note_id:int}", methods=["GET"])
    async def read_note(request):
        note_id = request.path_params["note_id"]
        query = notes.select().where(notes.c.id == note_id)
        result = await request.database.fetchone(query)
        content = {"text": result["text"], "completed": result["completed"]}
        return JSONResponse(content)

    @app.route("/notes/{note_id:int}/text", methods=["GET"])
    async def read_note_text(request):
        note_id = request.path_params["note_id"]
        query = sqlalchemy.select([notes.c.text]).where(notes.c.id == note_id)
        text = await request.database.fetchval(query)
        return JSONResponse(text)

    return app


@pytest.mark.parametrize("database_url", DATABASE_URLS)
def test_database(database_url):
    app = get_app(database_url)
    with TestClient(app) as client:
        response = client.post(
            "/notes", json={"text": "buy the milk", "completed": True}
        )
        assert response.status_code == 200

        with pytest.raises(RuntimeError):
            response = client.post(
                "/notes",
                json={"text": "you wont see me", "completed": False},
                params={"raise_exc": "true"},
            )

        response = client.post(
            "/notes", json={"text": "walk the dog", "completed": False}
        )
        assert response.status_code == 200

        response = client.get("/notes")
        assert response.status_code == 200
        assert response.json() == [
            {"text": "buy the milk", "completed": True},
            {"text": "walk the dog", "completed": False},
        ]

        response = client.get("/notes/1")
        assert response.status_code == 200
        assert response.json() == {"text": "buy the milk", "completed": True}

        response = client.get("/notes/1/text")
        assert response.status_code == 200
        assert response.json() == "buy the milk"


@pytest.mark.parametrize("database_url", DATABASE_URLS)
def test_database_executemany(database_url):
    app = get_app(database_url)
    with TestClient(app) as client:
        response = client.get("/notes")
        print(response.json())

        data = [
            {"text": "buy the milk", "completed": True},
            {"text": "walk the dog", "completed": False},
        ]
        response = client.post("/notes/bulk_create", json=data)
        assert response.status_code == 200

        response = client.get("/notes")
        print(response.json())
        assert response.status_code == 200
        assert response.json() == [
            {"text": "buy the milk", "completed": True},
            {"text": "walk the dog", "completed": False},
        ]


@pytest.mark.parametrize("database_url", DATABASE_URLS)
def test_database_isolated_during_test_cases(database_url):
    """
    Using `TestClient` as a context manager
    """
    app = get_app(database_url)
    with TestClient(app) as client:
        response = client.post(
            "/notes", json={"text": "just one note", "completed": True}
        )
        assert response.status_code == 200

        response = client.get("/notes")
        assert response.status_code == 200
        assert response.json() == [{"text": "just one note", "completed": True}]

    with TestClient(app) as client:
        response = client.post(
            "/notes", json={"text": "just one note", "completed": True}
        )
        assert response.status_code == 200

        response = client.get("/notes")
        assert response.status_code == 200
        assert response.json() == [{"text": "just one note", "completed": True}]
