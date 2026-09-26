from fastapi.testclient import TestClient
from app import main


def test_kb_seed_search_edit_delete_and_customer_files(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB_PATH', tmp_path / 'test.db')
    main.init_db()
    role={'username':'tech','role':'admin'}
    main.app.dependency_overrides[main.get_current_user]=lambda:role
    try:
        client=TestClient(main.app)
        assert client.get('/api/v1/kb/articles?q=MFA').json()[0]['id']==1
        assert len(client.get('/api/v1/kb/articles/1').json()['steps'])==3
        payload={'title':'Printer fix','product':'LaserJet','category':'Hardware','summary':'Paper jam',
                 'steps':[{'title':'Clear tray','instructions':'Remove stuck paper'}]}
        article=client.post('/api/v1/kb/articles',json=payload)
        assert article.status_code==201,article.text
        aid=article.json()['id']
        assert client.get('/api/v1/kb/articles?q=stuck').json()[0]['id']==aid
        upload=client.post(f'/api/v1/workspace-files/article/{aid}',content=b'%PDF-1.7 test',headers={'Content-Type':'application/pdf','X-Filename':'fix.pdf'})
        assert upload.status_code==201,upload.text
        fid=upload.json()['id']
        assert client.get(f'/api/v1/workspace-files/{fid}').content==b'%PDF-1.7 test'
        customer=client.post('/api/v1/crm/customers',json={'name':'Dental Office'})
        assert customer.status_code==201,customer.text
        cid=customer.json()['id']
        picture=client.post(f'/api/v1/workspace-files/customer/{cid}',content=b'\x89PNG\r\n\x1a\nexample',headers={'Content-Type':'image/png','X-Filename':'desk.png'})
        assert picture.status_code==201,picture.text
        assert client.get(f'/api/v1/crm/customers/{cid}').json()['files'][0]['filename']=='desk.png'
        role['role']='readonly'
        assert client.get(f'/api/v1/workspace-files/{fid}').status_code==200
        assert client.post(f'/api/v1/workspace-files/customer/{cid}',content=b'a',headers={'Content-Type':'image/png','X-Filename':'a.png'}).status_code==403
        assert client.delete(f'/api/v1/kb/articles/{aid}').status_code==403
        role['role']='admin'
        assert client.delete(f'/api/v1/kb/articles/{aid}').status_code==200
        assert client.get(f'/api/v1/workspace-files/{fid}').status_code==404
        main.init_db()
        assert client.get(f'/api/v1/kb/articles/{aid}').status_code==404
        assert client.delete('/api/v1/kb/articles/1').status_code==200
        main.init_db()
        assert client.get('/api/v1/kb/articles/1').status_code==404
    finally:
        main.app.dependency_overrides.clear()
