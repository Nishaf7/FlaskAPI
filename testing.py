import requests

#data = requests.post("http://localhost:5000/customer_api/update_info/", data={'username': 'nishaf11', 'edit_password': '123456',
#                                                                         'edit_address': 'Cantt Lahore.'})

#data = requests.post("http://localhost:5000/customer_api/login/", data={'username': 'nishaf', 'password': '123456'})
#data = requests.post("http://localhost:5000/customer_api/signup/", data={'username': 'ahmed', 'password': '123', 'address': 'Cavalry Ground.'})
#data = requests.post("http://localhost:5000/customer_api/delete_customer/", data={'username': 'ahmed'})
#print(data.text)


data = requests.get("http://localhost:9200/shakespeare*/_search?q=line_number:e&size=1000")
data = data.json()
print(data)
for i in data['hits']['hits']:
    print(i['_source']["line_number"])
