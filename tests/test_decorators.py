from starlette import asgi_application, Response, TestClient


def test_sync_app():
    @asgi_application
    def app(request):
        return Response("hello, world", media_type="text/plain")

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "hello, world"


def test_async_app():
    @asgi_application
    async def app(request):
        body = await request.body()
        return Response(body, media_type="text/plain")

    client = TestClient(app)
    response = client.post("/", json={"hello": "world"})
    assert response.status_code == 200
    assert response.text == '{"hello": "world"}'
