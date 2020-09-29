import json,re
def get(search):
    if search is None:
        return 'None'
    return search.group()




with open('the_last_result.txt','r') as file_source:
    lines = file_source.readlines()
    for line in lines:
        ip = re.search(r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])',line)
        mac = re.search(r'(([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2})', line)
        vendor = re.search(r'([A-Za-z]{3,})', line)
        port = re.search(r'\{.*?\}', line)
        with open('json.txt','a') as f:
            f.write('{') #1
            f.write('"' + str(get(ip)[0:9]) + '"' + ':' + '{') #2
            f.write('"' + str(get(ip)) + '"' + ':') #3
            f.write('[') #4
            f.write('{') #5
            f.write('"mac"' + ':' + '"' + str(get(mac)) + '"'+ ',' ) #6
            f.write('"vendor"'+ ':' + '"' + str(get(vendor)) + '"' +',' ) #7
            f.write('"port-server"' + ':') #8
            f.write('{') #9
            port_dict = eval(get(port))

            if port_dict != None:
                for key,value in port_dict.items():
                    f.write('"' + key +'"' + ':' + '"' + str(value) + '"')
                    keys_list = list(port_dict.keys())
                    # print(keys_list)
                    if key != keys_list[-1]:
                        f.write(',')
            else:f.write('"异常条目”')

            # f.write('端口-服务') # 10-12
            f.write('}')#13
            f.write('}') #14
            f.write(']' )#15
            f.write('}')#16
            f.write('}')#17

            # print(port_dict)


with open('json.txt','r') as json1:
    data = json1.readlines()


    sorted_string = json.dumps(data, indent=4,sort_keys=True)
    string_jsonto = json.loads(sorted_string)
    print('看这里',sorted_string)
    print('解析结果',string_jsonto)
