import argparse
import asyncio
import configparser
import logging
import signal
import os
import sys

import pymongo
import motor.motor_asyncio

from aiohttp.web import Application

from tree_task.handlers import insert_element
from tree_task.handlers import get_token
from tree_task.handlers import get_hash
from tree_task.handlers import auth_middleware_factory
from tree_task.handlers import search_element
from tree_task.handlers import get_element

logger = logging.getLogger(__name__)


def create_mongo_client(config):
    client = motor.motor_asyncio.AsyncIOMotorClient(
        config['mongodb']['host'],
        config['mongodb'].getint('port')
    )
    db = client[config['mongodb']['dbname']]
    return client, db


async def create_db(config):
    _, db = create_mongo_client(config)
    await db.user.insert({
        'login': 'user',
        'passwd': get_hash(b'user')      # для тестовой задачи используем sha256
    })

    await db.user.ensure_index(
        'login',
        unique=True
    )

    await db.tree.insert({
        '_id': 1,                       # для простоты используем целые числа
        'text': 'Some text',
        'path': None,
    })

    await db.tree.ensure_index([
        ('text', pymongo.TEXT),
    ])

    await db.tree.ensure_index('path')


def create_app(loop, config, debug=False):
    app = Application(loop=loop, middlewares=[auth_middleware_factory])
    app['config'] = config
    client, db = create_mongo_client(config)
    app['client'] = client
    app['db'] = db
    app['secret_key'] = os.environ.get('SECRET_KEY')

    app.router.add_route('POST', '/auth', get_token)
    app.router.add_route('POST', '/tree', insert_element)
    app.router.add_route('GET', '/tree', get_element)
    app.router.add_route('GET', '/tree/search', search_element)
    return app


async def create_server(loop, config, debug):
    app = create_app(loop, config, debug)
    handler = app.make_handler()
    srv = await loop.create_server(handler, config['http']['host'], config['http'].getint('port'))
    logger.info("Server started")
    return app, srv, handler


async def cleanup(app, srv, handler):
    await asyncio.sleep(0.1)
    srv.close()
    await handler.finish_connections()
    await srv.wait_closed()
    logger.info('Done')


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--loglevel", action="store", dest="loglevel", default='DEBUG', choices=['DEBUG', 'INFO', 'WARNINGS', 'ERROR'], help="Log level")

    parser.add_argument("--config", action="store", dest="config", help="Path to config")

    parser.add_argument("--debug", action="store_true", dest="debug", help="Set asyncio debug mode")

    parser.add_argument("--createdb", action="store_true", dest="createdb", help="Create DB and exit")

    args = parser.parse_args()

    _format = '%(name)s:%(levelname)s %(module)s:%(lineno)d:%(asctime)s  %(message)s'
    logging.basicConfig(stream=sys.stdout, format=_format, level=getattr(logging, args.loglevel))

    config = configparser.ConfigParser()
    config.read(args.config)

    loop = asyncio.get_event_loop()
    if args.debug:
        loop.set_debug(True)

    if args.createdb:
        loop.run_until_complete(create_db(config))
        sys.exit()

    loop.add_signal_handler(signal.SIGINT, lambda: loop.stop())
    app, srv, handler = loop.run_until_complete(create_server(loop, config, args.debug))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(cleanup(app, srv, handler))
