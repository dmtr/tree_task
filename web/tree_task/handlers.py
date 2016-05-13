import json
import logging
import hashlib
import re

import aiohttp
import itsdangerous

from aiohttp.web import Response

logger = logging.getLogger(__name__)


def get_hash(s):
    h = hashlib.sha256()
    h.update(s)
    return h.hexdigest()


def make_token(secret_key, **kwargs):
    s = itsdangerous.URLSafeSerializer(secret_key)
    return s.dumps(kwargs)


def unsign_token(secret_key, token):
    try:
        s = itsdangerous.URLSafeSerializer(secret_key)
        return s.loads(token)
    except Exception as e:
        logger.exception('Could not unsign %s', e)


async def auth_middleware_factory(app, handler):
    async def auth_handler(request):
        logger.debug('headers %s, path %s, scheme %s', request.headers, request.path, request.scheme)
        if request.path != '/auth':
            try:
                j = await request.json()
                token = j.get('token')
            except json.decoder.JSONDecodeError:
                token = request.GET.get('token')

            token = unsign_token(request.app['secret_key'], token)
            user = await request.app['db'].user.find_one({
                    'login': token['user']
                })
            if not user:
                raise aiohttp.HttpProcessingError(code=401)

        return await handler(request)

    return auth_handler


async def get_json(request):
    try:
        return await request.json()
    except json.decoder.JSONDecodeError:
        raise aiohttp.HttpProcessingError(code=400)


async def get_token(request):
    j = await get_json(request)
    user = await request.app['db'].user.find_one({
        'login': j.get('login')
    })
    if user and get_hash(j.get('passwd').encode('utf8')) == user['passwd']:
        body = json.dumps({
            'token': make_token(request.app['secret_key'], user=user['login'])
        })
        return Response(
            body=body.encode('utf8'),
            status=200,
            headers={'Content-Type': 'application/json'}
        )

    raise aiohttp.HttpProcessingError(code=401)


def validate_request(r, *fields):
    errors = []
    for f in fields:
        if f not in r:
            errors.append('{0} is required'.format(f))
    return errors


async def insert_element(request):                                  # не обрабатывается ошибка при вставке элемента с существующим id!
    j = await get_json(request)
    errors = validate_request(j, 'parent_id', 'element_id', 'text')
    if errors:
        return Response(
                    body=json.dumps({'error': ','.join(errors)}).encode('utf8'),
                    status=400,
                    headers={'Content-Type': 'application/json'}
                )

    parent = await request.app['db'].tree.find_one({
        '_id': int(j['parent_id'])
    })

    if not parent:
        return Response(
            body=json.dumps({'error': 'parent not found'}).encode('utf8'),
            status=404,
            headers={'Content-Type': 'application/json'}
        )

    path = ''
    if parent['path']:
        path += parent['path']
    else:
        path += ','
    path += str(parent['_id']) + ','
    logger.debug('path %s', path)
    await request.app['db'].tree.insert({
        '_id': j['element_id'],
        'path': path,
        'text': j['text']
    })

    return Response(
            body=json.dumps({'ok': True}).encode('utf8'),
            status=201,
            headers={'Content-Type': 'application/json'}
        )


async def search_element(request):
    q = request.GET.get('query')
    if not q:
        raise aiohttp.HttpProcessingError(code=400)
    elements = []
    async for e in request.app['db'].tree.find({'$text': {'$search': q}}):
        elements.append(e)
    return Response(
            body=json.dumps({'elements': elements}).encode('utf8'),
            status=200,
            headers={'Content-Type': 'application/json'}
        )


async def get_element(request):
    _id = request.GET.get('id')
    if not _id:
        raise aiohttp.HttpProcessingError(code=400)

    parent = await request.app['db'].tree.find_one({
        '_id': int(_id)
    })

    if not parent:
        return Response(
            body=json.dumps({'error': 'element not found'}).encode('utf8'),
            status=404,
            headers={'Content-Type': 'application/json'}
        )
    elements = [parent]
    regex = re.compile(',{0},'.format(_id))
    logger.debug('regex %s', regex)
    async for e in request.app['db'].tree.find({'path': regex}):
        elements.append(e)
    return Response(
            body=json.dumps({'elements': elements}).encode('utf8'),
            status=200,
            headers={'Content-Type': 'application/json'}
        )
