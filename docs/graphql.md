
Starlette includes optional support for GraphQL, using the `graphene` library.

Here's an example of integrating the support into your application.

```python
from starlette.applications import Starlette
from starlette.graphql import GraphQLApp
import graphene


class Query(graphene.ObjectType):
    hello = graphene.String(name=graphene.String(default_value="stranger"))

    def resolve_hello(self, info, name):
        return "Hello " + name


schema = graphene.Schema(query=Query)


app = Starlette()
app.add_route('/', GraphQLApp(schema=schema), methods=['GET', 'POST'])
```

## Sync or Async executors

If you're working with a standard ORM, then just use regular function calls for
your "resolve" methods, and Starlette will manage running the GraphQL query within a
seperate thread.

If you want to use an asyncronous ORM, then use "async resolve" methods, and
make sure to setup Graphene's AsyncioExecutor.

```python
from graphql.execution.executors.asyncio import AsyncioExecutor
from starlette.applications import Starlette
from starlette.graphql import GraphQLApp
import graphene


class Query(graphene.ObjectType):
    hello = graphene.String(name=graphene.String(default_value="stranger"))

    async def resolve_hello(self, info, name):
        # We can make asynchronous network calls here.
        return "Hello " + name


schema = graphene.Schema(query=Query)


app = Starlette()
app.add_route('/', GraphQLApp(schema=schema, executor=AsyncioExecutor()), methods=['GET', 'POST'])
```
