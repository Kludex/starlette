
Starlette includes optional support for GraphQL, using the `graphene` library.

Here's an example of integrating the support into your application.

```python
from starlette.applications import Starlette
import graphene


class Query(graphene.ObjectType):
    hello = graphene.String(name=graphene.String(default_value="stranger"))

    def resolve_hello(self, info, name):
        return "Hello " + name


app = Starlette()
app.add_graphql_route('/', schema=graphene.Schema(query=Query))
```

If you load up the page in a browser, you'll be served the GraphiQL tool,
which you can use to interact with your GraphQL API.

![GraphiQL](img/graphiql.png)

## Sync or Async executors

If you're working with a standard ORM, then just use regular function calls for
your "resolve" methods, and Starlette will manage running the GraphQL query within a
seperate thread.

If you want to use an asyncronous ORM, then use "async resolve" methods, and
make sure to setup Graphene's AsyncioExecutor using the `executor` argument.

```python
from graphql.execution.executors.asyncio import AsyncioExecutor
from starlette.applications import Starlette
import graphene


class Query(graphene.ObjectType):
    hello = graphene.String(name=graphene.String(default_value="stranger"))

    async def resolve_hello(self, info, name):
        # We can make asynchronous network calls here.
        return "Hello " + name


app = Starlette()

# We're using `executor=AsyncioExecutor()` here.
app.add_graphql_route('/', schema=graphene.Schema(query=Query), executor=AsyncioExecutor())
```
