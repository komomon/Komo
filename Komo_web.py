from datetime import datetime
import json
import os
import queue

from loguru import logger
from flask import Flask, request, render_template, jsonify
import fire
from urllib.parse import parse_qs
# import test4
import threading
import Komo

app = Flask(__name__)

app_root = os.path.dirname(os.path.abspath(__file__))
app_template_path = os.path.join(app_root, 'static/templates')
app.static_folder = 'static/templates'
app.template_folder = app_template_path


# Req_Data = {}
# Task_queue = queue.Queue()  # 创建一个空队列

def create_logfile():
    if os.path.exists(f'{os.getcwd()}/log') is False:
        os.makedirs(f'{os.getcwd()}/log')
    logger.add(sink='log/web.log', level='INFO', encoding='utf-8')
    logger.add(sink='log/web_error.log', level='ERROR', encoding='utf-8')


def get_user_defined_attrs_and_methods(obj):
    '''
    获取类的函数和参数名称
    :param obj:
    :return:
    '''
    user_defined_attrs = []
    user_defined_methods = []

    for attr_name in dir(obj):
        # 判断属性是否为用户定义的变量
        if not attr_name.startswith("__") and not callable(getattr(obj, attr_name)):
            user_defined_attrs.append(attr_name)

        # 判断属性是否为用户定义的方法
        elif not attr_name.startswith("__") and callable(getattr(obj, attr_name)):
            user_defined_methods.append(attr_name)

    return user_defined_attrs, user_defined_methods


Komo_Params, Komo_Functions = get_user_defined_attrs_and_methods(Komo.Komo())


# 获取去请求参数
def request_parse(req_data):
    '''解析请求数据并以json形式返回'''
    data = {}
    try:
        if req_data.method == 'POST':
            # data = req_data.json
            if req_data.headers['Content-Type'] == 'application/json':
                # 请求参数是 JSON 数据
                data = json.loads(req_data.json)
                # TODO: 处理 JSON 数据
            elif req_data.headers['Content-Type'] in (
                    'application/x-www-form-urlencoded', 'application/x-www-form-urlencoded;charset=UTF-8',
                    'multipart/form-data'):
                # 请求参数是表单数据
                data = req_data.form.to_dict()
                # TODO: 处理表单数据
            # elif request.headers['Content-Type'] == 'text/plain':
            #     data = request.data.decode('utf-8')
            #     # 对文本数据进行处理
            #     data = json.loads(data)
            # data = parse_qs(data)
            else:
                try:
                    data = json.loads(req_data.json)
                except:
                    pass
                try:
                    data = req_data.form.to_dict()
                except:
                    pass
        elif req_data.method == 'GET':
            data = req_data.args.to_dict()
    except Exception as e:
        logger.error(e)
    return data


# 下发任务
def handle_task(data, params, functions):
    # global Komo_Params,Komo_Functions
    print('start')
    print(data)
    # print(params)
    # print(functions)
    Task_list = []
    # 处理记录任务
    if os.path.exists('core/data/task.txt'):
        if os.path.getsize('core/data/task.txt'):
            with open('core/data/task.txt', "r", encoding="utf-8") as f:
                # 先读取
                for line in f.readlines():
                    task = json.loads(line)
                    Task_list.append(task)
                # print("gangduwan",Task_list)
                # 没有的话再加进去
                if data not in Task_list:
                    # print("data:",data)
                    Task_list.append(data)
                    logger.info(f"[+] add task:{data}")
        else:
            Task_list.append(data)
            logger.info(f"[+] add task:{data}")
    else:  # 如何存在则读取任务
        Task_list.append(data)
        logger.info(f"[+] add task:{data}")
    # print(Task_list)
    with open('core/data/task.txt', "w", encoding="utf-8") as f:
        for task in Task_list:
            # print(json.dumps(task))
            f.write(json.dumps(task) + '\n')

    while Task_list:
        print('Task_list:', Task_list)
        task = Task_list[0]
        print("functions:", functions)
        if task['functions'] and task['functions'] in functions:
            for param in params:
                if param not in task.keys():
                    task[param] = None
            print('task content', task)
            ko = Komo.Komo(json_data=task)
            getattr(ko, task['functions'])()
            # 扫描完成则更新队列文件
            # if os.path.exists('core/data/completed'):
            Task_list.remove(task)
            logger.info(f"[+] task finised:{task}")
            # 写入已完成列表
            date1 = str(datetime.now().strftime("%Y-%m-%d-%H-%M-%S"))
            with open('core/data/tasks_done.txt', "a", encoding="utf-8") as f:
                f.write(date1+','+json.dumps(task) + '\n')
            # with open('core/data/task.txt', "r", encoding="utf-8") as f:
            #     Task_list = list(json.loads(f.read()))
            # 要扫描的去掉
            with open('core/data/tasks.txt', "w", encoding="utf-8") as f:
                for task in Task_list:
                    f.write(json.dumps(task) + '\n')

            # os.remove('core/data/completed')
        else:
            continue


@app.route('/')
def index():
    # return 'Hello World!'
    return render_template('index.html')
    # return render_template('index.html', data=data)


@app.route('/getinfo')
def getinfo():
    '''
    从komo主文件获取函数和变量，返回给前端
    :return:
    '''
    global Komo_Params, Komo_Functions
    # data = {
    # "params": ['attackflag', 'date', 'domain', 'domains', 'domains_list', 'ip', 'ips', 'params', 'proxy', 'randomstr', 'result_folder', 'subdomain', 'subdomains', 'url', 'urlsfile'],
    # "functions":  ['all', 'all2', 'all3', 'attack', 'collect', 'collect1', 'email', 'finger', 'hostattack', 'install', 'portscan', 'sensitive', 'sub', 'survival', 'webattack', 'webattack1', 'webattack2']
    # }
    # Komo_Params = ['attackflag', 'date', 'domain', 'domains', 'domains_list', 'ip', 'ips', 'params', 'proxy', 'randomstr', 'result_folder', 'subdomain', 'subdomains', 'url', 'urlsfile']
    # Komo_Functions = ['all', 'all2', 'all3', 'attack', 'collect', 'collect1', 'email', 'finger', 'hostattack', 'install', 'portscan', 'sensitive', 'sub', 'survival', 'webattack', 'webattack1', 'webattack2']
    data = {
        "params": Komo_Params,
        "functions": Komo_Functions
    }
    return jsonify(data)


@app.route('/start', methods=['GET', 'POST'])
def start():
    '''
    下发任务
    :return:
    '''
    # data = {
    # "params": ['attackflag', 'date', 'domain', 'domains', 'domains_list', 'ip', 'ips', 'params', 'proxy', 'randomstr', 'result_folder', 'subdomain', 'subdomains', 'url', 'urlsfile'],
    # "functions":  ['all', 'all2', 'all3', 'attack', 'collect', 'collect1', 'email', 'finger', 'hostattack', 'install', 'portscan', 'sensitive', 'sub', 'survival', 'webattack', 'webattack1', 'webattack2']
    # }
    global Komo_Params, Komo_Functions
    req_data = request_parse(request)
    logger.info(f"[+] request data:{req_data}") #  {'subdomain': 'aaa', 'urlsfile': 'aaa', 'functions': 'test'}
    # print(req_data)
    # return jsonify(data)
    # req_data_keys = Req_Data.keys()
    # 如果有则先读
    if req_data['functions']:
        t = threading.Thread(target=handle_task, args=(req_data, Komo_Params, Komo_Functions))  #
        t.start()
        # t = threading.Thread(target=execute_task, args=(params,))
        # fire.Fire(getattr(test4, "AA"))
        return jsonify({"status": "success"})
    else:
        # Req_Data = {}
        return jsonify({"status": "failed,没有指定functions!"})

# 测试用
# @app.route('/test3')
# def test3():
#     # return 'Hello World!'
#     # data = get_user_defined_attrs_and_methods(Komo.Komo())
#     #
#     # data = {
#     #     "a": ['a', 'b'],
#     #     "b": ['aaa', 'bbb']
#     # }
#     # return render_template('test2.html', data=data)
#     return render_template('test3.html')


# @app.route('/<function_name>', methods=['GET', 'POST'])
# def call_function(function_name):
#     # print(request.headers)
#     args = request_parse(request)
#     print(args)
#     # result = fire.Fire(getattr(test4, function_name), **args)
#     return args


def webhook(host='127.0.0.1', port=8001):
    app.run(host='127.0.0.1', port=8001)
    # app.run(host='127.0.0.1', port=8001, debug=True, use_reloader=True)


if __name__ == '__main__':
    # app.run()
    app.run(host='127.0.0.1', port=8001, debug=True, use_reloader=True)
    # result = fire.Fire(getattr(test4, "AA"))
    # python test3.py --a=1 --b=2 aaa
    # print(result)
    # print(dir(test4.AA))
