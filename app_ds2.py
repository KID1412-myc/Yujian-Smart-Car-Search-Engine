import os
from dotenv import load_dotenv
load_dotenv()
import traceback
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from elasticsearch import Elasticsearch, NotFoundError
from openai import OpenAI
import re
import json
import sys
import subprocess
import time
from werkzeug.utils import secure_filename

MAPPING_FILE_PATH = os.path.join(os.path.dirname(__file__), 'feature_mapping.json')
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, get_jwt_identity,
    jwt_required, set_access_cookies, unset_jwt_cookies,
    JWTManager, get_jwt
)
import bcrypt
from datetime import timedelta
from flask_migrate import Migrate
from functools import wraps

# 核心配置 (AI, ES, Flask)
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
DEEPSEEK_MODEL_NAME = "deepseek-chat"
PROXY_URL = ""
ES_HOST = "localhost"
ES_PORT = 9200
INDEX_NAME = "yiche_cars"
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'temp_uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
CRAWLER_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'web_crawler_dynamic.py')
IMPORTER_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), 'web_batch_importer.py')
CRAWLER_OUTPUT_FILE = "latest_crawl_output.csv"
CRAWLER_STATUS_FILE = os.path.join(os.path.dirname(__file__), "crawler.status")
CRAWLER_LOG_FILE = os.path.join(os.path.dirname(__file__), "crawler.log")
app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY")
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_COOKIE_SAMESITE_POLICY"] = "None"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=30)

db = SQLAlchemy(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)

# AI 服务配置
try:
    if PROXY_URL:
        os.environ['http_proxy'] = PROXY_URL
        os.environ['https_proxy'] = PROXY_URL
    llm_client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")
    print("AI 服务配置成功！")
except Exception as e:
    print(f"AI 服务配置失败: {e}")
    llm_client = None

# ES 配置
try:
    es_client = Elasticsearch([{'host': ES_HOST, 'port': ES_PORT, 'scheme': 'http'}])
    if not es_client.ping():
        raise ConnectionError("无法连接到Elasticsearch")
    print(f"后端成功连接到Elasticsearch！目标索引: {INDEX_NAME}")
except Exception as e:
    print(f"连接Elasticsearch失败: {e}")
    es_client = None

# 加载特性映射文件
FEATURE_MAPPING = {}
MAPPING_FILE_PATH = os.path.join(os.path.dirname(__file__), 'feature_mapping.json')
try:
    with open(MAPPING_FILE_PATH, 'r', encoding='utf-8') as f:
        FEATURE_MAPPING = json.load(f)
    print(f"特性映射文件 {MAPPING_FILE_PATH} 加载成功！共 {len(FEATURE_MAPPING)} 个特性。")
except FileNotFoundError:
    print(f"警告：特性映射文件 feature_mapping.json 未找到，特性搜索将回退到AI解析。")
except json.JSONDecodeError as e:
    print(f"错误：解析特性映射文件 feature_mapping.json 失败: {e}")
except Exception as e:
    print(f"加载特性映射文件时发生未知错误: {e}")


# 数据库模型 (Python类 映射 MySQL表)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    hashed_password = db.Column(db.String(255), nullable=False)
    nickname = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(50), nullable=False, default='user')
    is_banned = db.Column(db.Boolean, nullable=False, default=False)
    ban_reason = db.Column(db.Text, nullable=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True, cascade="all, delete-orphan")

    def __init__(self, username, password, nickname=None):
        self.username = username
        self.hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        if nickname:
            self.nickname = nickname
        else:
            self.nickname = username

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.hashed_password.encode('utf-8'))


class Favorite(db.Model):
    __tablename__ = 'favorites'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    model_id = db.Column(db.String(255), nullable=False)
    series_name = db.Column(db.String(255), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'model_id', name='_user_model_uc'),)


class SystemConfig(db.Model):
    __tablename__ = 'system_config'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=True)

    def __init__(self, key, value):
        self.key = key
        self.value = value


# 辅助函数：验证高危操作密码
def _verify_high_risk_password(password):
    if not password:
        return False, "必须提供高危操作密码"
    config = SystemConfig.query.get('high_risk_password')

    if not config or not config.value:
        return False, "高危操作密码尚未设置，操作被阻止。请核心管理员先设置密码。"
    if bcrypt.checkpw(password.encode('utf-8'), config.value.encode('utf-8')):
        return True, "验证通过"
    else:
        return False, "高危操作密码不正确"


def parse_price_to_numeric(price_str):
    if not isinstance(price_str, str) or '万' not in price_str:
        return None
    match = re.search(r'(\d+\.?\d*)', price_str)
    if match:
        try:
            return float(match.group(1))
        except (ValueError, IndexError):
            return None
    return None


def clean_power_type(energy_type_str):
    if not isinstance(energy_type_str, str): return '未知'
    if '插电混' in energy_type_str: return '插电混动'
    if '增程' in energy_type_str: return '增程式'
    if '油电混' in energy_type_str: return '油电混合'
    if '轻混' in energy_type_str: return '轻混系统'
    if '氢' in energy_type_str: return '氢能源'
    if '汽油' in energy_type_str: return '燃油'
    if '纯电' in energy_type_str: return '纯电'
    return energy_type_str if energy_type_str else '未知'


def clean_body_type(level_str):
    if not isinstance(level_str, str): return '其他'
    if 'SUV' in level_str.upper(): return 'SUV'
    if 'MPV' in level_str.upper(): return 'MPV'
    if '跑车' in level_str: return '跑车'
    if '旅行车' in level_str: return '旅行车'
    if '掀背车' in level_str: return '掀背车'
    if '敞篷车' in level_str: return '敞篷车'
    if '皮卡' in level_str: return '皮卡'
    if '两厢车' in level_str or '三厢车' in level_str: return '轿车'
    return '其他'


def clean_seat_count(structure_str):
    if not isinstance(structure_str, str): return None
    if '2座' in structure_str: return '2座'
    if '4座' in structure_str: return '4座'
    if '5座' in structure_str: return '5座'
    if '6座' in structure_str: return '6座'
    if '7座' in structure_str: return '7座'
    return None


def clean_segment(level_str):
    if not isinstance(level_str, str): return None
    if '小型' in level_str: return '小型'
    if '紧凑型' in level_str: return '紧凑型'
    if '中型' in level_str: return '中型'
    if '中大型' in level_str: return '中大型'
    if '大型' in level_str: return '大型'
    return None


def get_current_user_from_jwt():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))
        return user
    except Exception:
        return None


def core_admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            user = get_current_user_from_jwt()
            if user and user.role == 'core_admin':
                return fn(*args, **kwargs)
            else:
                return jsonify({"error": "权限不足：需要核心管理员权限"}), 403

        return decorator

    return wrapper


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            user = get_current_user_from_jwt()
            if user and (user.role == 'admin' or user.role == 'core_admin'):
                return fn(*args, **kwargs)
            else:
                return jsonify({"error": "权限不足：需要管理员权限"}), 403

        return decorator

    return wrapper


@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "必须提供用户名和密码"}), 400
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"error": "该用户名已被占用"}), 409
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "注册成功！"}), 201

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"注册时发生内部错误: {str(e)}"}), 500


@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "必须提供用户名和密码"}), 400

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            return jsonify({"error": "用户名或密码错误"}), 401

        if user.is_banned:
            reason = user.ban_reason if user.ban_reason else "无特定原因"
            return jsonify({
                "error": "此账户已被封禁",
                "reason": reason
            }), 403

        access_token = create_access_token(identity=str(user.id))

        response_data = {
            "message": "登录成功",
            "user": {
                "username": user.username,
                "nickname": user.nickname,
                "role": user.role
            }
        }

        response = jsonify(response_data)
        set_access_cookies(response, access_token)

        print(f"   -> (登录成功: {username}, 角色: {user.role})")
        return response, 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"登录时发生内部错误: {str(e)}"}), 500


@app.route('/auth/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "退出登录成功"})
    unset_jwt_cookies(response)
    return response, 200


@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=int(current_user_id)).first()

        if not user:
            return jsonify({"error": "用户不存在"}), 404

        return jsonify({
            "id": user.id,
            "username": user.username,
            "nickname": user.nickname,
            "role": user.role
        }), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"获取用户信息时发生内部错误: {str(e)}"}), 500


@app.route('/api/profile/update', methods=['POST'])
@jwt_required()
def update_profile():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=int(current_user_id)).first()

        if not user:
            return jsonify({"error": "用户不存在"}), 404

        data = request.json
        new_nickname = data.get('nickname')

        if not new_nickname or len(new_nickname.strip()) == 0:
            return jsonify({"error": "昵称不能为空"}), 400

        user.nickname = new_nickname.strip()
        db.session.commit()

        print(f"   -> (用户 {user.username} 昵称更新为: {new_nickname})")
        return jsonify({"message": "昵称更新成功", "nickname": user.nickname}), 200

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"更新昵称时发生内部错误: {str(e)}"}), 500


@app.route('/api/profile/change_password', methods=['POST'])
@jwt_required()
def change_password():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))
        if not user:
            return jsonify({"error": "用户不存在"}), 404

        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({"error": "缺少必要参数"}), 400

        if not user.check_password(current_password):
            return jsonify({"error": "当前密码不正确"}), 401
        user.hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db.session.commit()

        print(f"   -> (用户 {user.username} 密码已更新)")
        return jsonify({"message": "密码更新成功"}), 200

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"更新密码时发生内部错误: {str(e)}"}), 500


@app.route('/api/favorites', methods=['GET'])
@jwt_required()
def get_favorites():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=int(current_user_id)).first()

        if not user:
            response = jsonify({"error": "用户不存在"})
            unset_jwt_cookies(response)
            return response, 404

        favorites = user.favorites
        fav_list = [{"id": f.model_id, "series": f.series_name} for f in favorites]

        return jsonify(fav_list), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"获取收藏时发生内部错误: {str(e)}"}), 500


@app.route('/api/favorites/add', methods=['POST'])
@jwt_required()
def add_favorite():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=int(current_user_id)).first()

        if not user:
            return jsonify({"error": "用户不存在"}), 404

        data = request.json
        model_id = data.get('model_id')
        series_name = data.get('series_name')

        if not model_id or not series_name:
            return jsonify({"error": "缺少 model_id 或 series_name"}), 400

        existing_fav = Favorite.query.filter_by(user_id=user.id, model_id=model_id).first()
        if existing_fav:
            return jsonify({"message": "已收藏"}), 200

        new_fav = Favorite(user_id=user.id, model_id=model_id, series_name=series_name)
        db.session.add(new_fav)
        db.session.commit()

        print(f"   -> (用户ID {user.id} 添加收藏: {model_id})")
        return jsonify({"message": "添加收藏成功"}), 201

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"添加收藏时发生内部错误: {str(e)}"}), 500


@app.route('/api/favorites/remove', methods=['POST'])
@jwt_required()
def remove_favorite():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=int(current_user_id)).first()

        if not user:
            return jsonify({"error": "用户不存在"}), 404

        data = request.json
        model_id = data.get('model_id')

        if not model_id:
            return jsonify({"error": "缺少 model_id"}), 400

        fav_to_remove = Favorite.query.filter_by(user_id=user.id, model_id=model_id).first()

        if fav_to_remove:
            db.session.delete(fav_to_remove)
            db.session.commit()
            print(f"   -> (用户ID {user.id} 移除收藏: {model_id})")
            return jsonify({"message": "移除收藏成功"}), 200
        else:
            return jsonify({"message": "收藏不存在"}), 404

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"移除收藏时发生内部错误: {str(e)}"}), 500


@app.route('/search', methods=['POST'])
def search():
    if not es_client:
        return jsonify({"error": "数据库服务未连接"}), 503
    try:
        data = request.get_json()
        page = data.get('page', 1)
        per_page = data.get('per_page', 12)

        sort_by = data.get('sort_by', 'relevance')

        filter_conditions = [
            {"term": {"is_koubei_row": False}},
            {"exists": {"field": "车系名称.keyword"}}
        ]
        brand = data.get('brand')
        if brand and brand != '所有品牌':
            filter_conditions.append({"term": {"品牌.keyword": brand}})
        manufacturer = data.get('manufacturer')
        if manufacturer and manufacturer != '所有厂商':
            if isinstance(manufacturer, list):
                filter_conditions.append({"terms": {"基本信息_厂商.keyword": manufacturer}})
            else:
                filter_conditions.append({"term": {"基本信息_厂商.keyword": manufacturer}})
        price_min = data.get('price_min')
        price_max = data.get('price_max')
        if price_min is not None and price_max is not None and (price_min > 0 or price_max > 0):
            price_filter = {}
            if price_min > 0: price_filter["gte"] = price_min
            if price_max > 0: price_filter["lte"] = price_max
            filter_conditions.append({"range": {"price_numeric": price_filter}})
        power_type = data.get('power_type')
        if power_type and power_type != '不限':
            filter_conditions.append({"term": {"动力类型": power_type}})
        body_type = data.get('body_type')
        if body_type and body_type != '不限':
            filter_conditions.append({"term": {"车身类型": body_type}})
        seat_count = data.get('seat_count')
        if seat_count and seat_count != '不限':
            filter_conditions.append({"term": {"车身_座位数": seat_count}})
        segment = data.get('segment')
        if segment and segment != '不限':
            filter_conditions.append({"term": {"基本信息_级别": segment}})
        search_query = data.get('q', '').strip()

        base_query = {
            "bool": {
                "must": filter_conditions,
                "should": [],
                "minimum_should_match": 0
            }
        }

        if search_query:
            base_query["bool"]["minimum_should_match"] = 1

            base_query["bool"]["should"].append({
                "match": {
                    "车系名称": {
                        "query": search_query,
                        "boost": 20.0,
                        "analyzer": "my_custom_search_analyzer"
                    }
                }
            })
            base_query["bool"]["should"].append({
                "match_phrase_prefix": {
                    "车系名称": {
                        "query": search_query,
                        "boost": 15.0,
                        "analyzer": "my_custom_search_analyzer"
                    }
                }
            })
            base_query["bool"]["should"].append({
                "multi_match": {
                    "query": search_query,
                    "fields": ["车型名称", "品牌", "基本信息_厂商"],
                    "type": "phrase_prefix",
                    "boost": 10.0,
                    "analyzer": "my_custom_search_analyzer"
                }
            })

            base_query["bool"]["should"].append({
                "wildcard": {
                    "车系名称.keyword": {
                        "value": f"*{search_query}*",
                        "boost": 9.0,
                        "case_insensitive": True
                    }
                }
            })

            base_query["bool"]["should"].append({
                "wildcard": {
                    "车型名称.keyword": {
                        "value": f"*{search_query}*",
                        "boost": 8.0,
                        "case_insensitive": True
                    }
                }
            })
            base_query["bool"]["should"].append({
                "multi_match": {
                    "query": search_query,
                    "fields": ["车型名称", "车系名称", "品牌"],
                    "type": "most_fields",
                    "fuzziness": "AUTO",
                    "boost": 1.0
                }
            })
            final_query = base_query
        else:
            final_query = base_query

        sort_order_config = {
            "max_relevance_score": "desc"
        }
        if sort_by == 'price_asc':
            sort_order_config = {"min_price": "asc"}
        elif sort_by == 'price_desc':
            sort_order_config = {"max_price": "desc"}

        es_query = {
            "query": final_query,
            "size": 0,
            "aggs": {
                "unique_series": {
                    "terms": {
                        "field": "车系名称.keyword",
                        "size": 1000,
                        "order": sort_order_config
                    },
                    "aggs": {
                        "max_relevance_score": {"max": {"script": "_score"}},
                        "a_representative_doc": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["车系名称", "图片链接", "基本信息_厂商"]
                            }
                        },
                        "min_price": {"min": {"field": "price_numeric", "missing": 99999}},
                        "max_price": {"max": {"field": "price_numeric", "missing": 0}},
                        "power_types": {"terms": {"field": "动力类型"}},
                        "body_types": {"terms": {"field": "车身类型"}},
                        "seat_counts": {"terms": {"field": "车身_座位数"}},
                        "segments": {"terms": {"field": "基本信息_级别"}}
                    }
                }
            }
        }

        response = es_client.search(index=INDEX_NAME, body=es_query)
        buckets = response['aggregations']['unique_series']['buckets']
        total_series = len(buckets)
        paginated_buckets = buckets[(page - 1) * per_page: page * per_page]
        results = []
        for bucket in paginated_buckets:
            hit_source = bucket['a_representative_doc']['hits']['hits'][0]['_source']
            min_p = bucket['min_price']['value']
            max_p = bucket['max_price']['value']

            if min_p == 99999: min_p = None
            if max_p == 0: max_p = None

            price_range = "暂无价格"
            if min_p is not None and max_p is not None:
                price_range = f"{min_p:.2f}万" if min_p == max_p else f"{min_p:.2f}-{max_p:.2f}万"
            elif min_p is not None:
                price_range = f"{min_p:.2f}万起"
            elif max_p is not None:
                price_range = f"{max_p:.2f}万"

            power_types_list = [item['key'] for item in bucket['power_types']['buckets']]
            body_types_list = [item['key'] for item in bucket['body_types']['buckets']]
            seat_counts_list = [item['key'] for item in bucket['seat_counts']['buckets']]
            segments_list = [item['key'] for item in bucket['segments']['buckets']]
            results.append({
                "_source": {
                    "厂商": hit_source.get("基本信息_厂商"),
                    "车系名称": hit_source.get("车系名称"),
                    "图片链接": hit_source.get("图片链接", "default_image_url.jpg"),
                    "价格范围": price_range,
                    "动力类型列表": power_types_list,
                    "车身类型列表": body_types_list,
                    "座位数列表": seat_counts_list,
                    "级别列表": segments_list
                }
            })
        return jsonify({'total': total_series, 'hits': results})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e), 'total': 0, 'hits': []}), 500


@app.route('/get-brands-and-manufacturers', methods=['GET'])
def get_brands_and_manufacturers():
    if not es_client:
        return jsonify({"error": "数据库服务未连接"}), 503
    try:
        es_query = {
            "query": {
                "bool": {"must": [{"term": {"is_koubei_row": False}}, {"exists": {"field": "车系名称.keyword"}}]}
            },
            "size": 0,
            "aggs": {
                "brands": {
                    "terms": {"field": "品牌.keyword", "size": 500},
                    "aggs": {
                        "manufacturers": {"terms": {"field": "基本信息_厂商.keyword", "size": 100}}
                    }
                }
            }
        }
        response = es_client.search(index=INDEX_NAME, body=es_query)
        brand_to_manufacturers = {}
        for brand_bucket in response['aggregations']['brands']['buckets']:
            brand_name = brand_bucket['key']
            manufacturers_list = [manu_bucket['key'] for manu_bucket in brand_bucket['manufacturers']['buckets']]
            if brand_name and manufacturers_list:
                brand_to_manufacturers[brand_name] = manufacturers_list
        return jsonify(brand_to_manufacturers)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/details', methods=['GET'])
def get_details():
    if not es_client:
        return jsonify({"error": "数据库服务未连接"}), 503
    try:
        series_name = request.args.get('series_name', type=str)
        if not series_name:
            return jsonify({"error": "必须提供车系名称"}), 400
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)

        query_conditions_must = [
            {"term": {"车系名称.keyword": series_name}},
            {"term": {"is_koubei_row": False}}
        ]
        query_conditions_should = []

        price_min = request.args.get('price_min', 0, type=float)
        price_max = request.args.get('price_max', 0, type=float)
        if price_min > 0 or price_max > 0:
            price_filter = {}
            if price_min > 0: price_filter["gte"] = price_min
            if price_max > 0: price_filter["lte"] = price_max
            query_conditions_must.append({"range": {"price_numeric": price_filter}})
        power_type = request.args.get('power_type', type=str)
        if power_type and power_type != '不限':
            query_conditions_must.append({"term": {"动力类型": power_type}})
        body_type = request.args.get('body_type', type=str)
        if body_type and body_type != '不限':
            query_conditions_must.append({"term": {"车身类型": body_type}})
        seat_count = request.args.get('seat_count', type=str)
        if seat_count and seat_count != '不限':
            query_conditions_must.append({"term": {"车身_座位数": seat_count}})
        segment = request.args.get('segment', type=str)
        if segment and segment != '不限':
            query_conditions_must.append({"term": {"基本信息_级别": segment}})

        search_query = request.args.get('q', '').strip()

        if search_query:
            print(f"   -> Details Page Search: '{search_query}' - Sorting by relevance.")

            query_conditions_should.append({
                "multi_match": {"query": search_query, "fields": ["车型名称"], "type": "bool_prefix", "boost": 10.0,
                                "analyzer": "my_custom_search_analyzer"}
            })
            query_conditions_should.append({
                "wildcard": {"车型名称.keyword": {"value": f"*{search_query}*", "boost": 8.0, "case_insensitive": True}}
            })
            query_conditions_should.append({
                "multi_match": {"query": search_query, "fields": ["车型名称"], "type": "most_fields",
                                "fuzziness": "AUTO", "boost": 1.0}
            })

            es_query = {
                "from": (page - 1) * per_page, "size": per_page,
                "query": {"bool": {"must": query_conditions_must, "should": query_conditions_should,
                                   "minimum_should_match": 1}},
                "sort": [{"_score": {"order": "desc"}}, {"price_numeric": {"order": "asc", "missing": "_last"}}]
            }
        else:
            print("   -> Details Page Browse - Sorting by price.")
            es_query = {
                "from": (page - 1) * per_page, "size": per_page,
                "query": {"bool": {"must": query_conditions_must}},
                "sort": [{"price_numeric": {"order": "asc", "missing": "_last"}}]
            }

        response = es_client.search(index=INDEX_NAME, body=es_query)
        hits = [hit['_source'] for hit in response['hits']['hits']]
        total_hits = response['hits']['total']['value']
        return jsonify({'hits': hits, 'total': total_hits, 'page': page, 'per_page': per_page})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"获取车型详情时发生内部错误: {e}"}), 500


@app.route('/get-series-by-manufacturer', methods=['GET'])
def get_series_by_manufacturer():
    if not es_client:
        return jsonify({"error": "数据库服务未连接"}), 503
    try:
        brand = request.args.get('brand', type=str)
        manufacturer = request.args.get('manufacturer', type=str)
        if not brand:
            return jsonify({"error": "必须提供品牌名称"}), 400
        query_conditions = [
            {"term": {"is_koubei_row": False}},
            {"term": {"品牌.keyword": brand}}
        ]
        if manufacturer and manufacturer != "所有厂商":
            query_conditions.append({"term": {"基本信息_厂商.keyword": manufacturer}})
        es_query = {
            "query": {"bool": {"must": query_conditions}},
            "size": 0,
            "aggs": {"series_names": {"terms": {"field": "车系名称.keyword", "size": 500}}}
        }
        response = es_client.search(index=INDEX_NAME, body=es_query)
        series_list = [bucket['key'] for bucket in response['aggregations']['series_names']['buckets']]
        return jsonify(series_list)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/search-models', methods=['GET'])
def search_models():
    if not es_client:
        return jsonify({"error": "数据库服务未连接"}), 503
    try:
        q = request.args.get('q', '').strip()
        if not q:
            return jsonify({"error": "查询词不能为空"}), 400

        must_conditions = [
            {"term": {"is_koubei_row": False}},
            {"exists": {"field": "车型名称.keyword"}}
        ]
        series_name = request.args.get('series_name', type=str, default=None)
        if series_name:
            must_conditions.append({"term": {"车系名称.keyword": series_name}})
            print(f"   -> (Autocomplete: 锁定车系 {series_name})")

        es_query = {
            "query": {
                "bool": {
                    "must": must_conditions,
                    "should": [
                        {
                            "multi_match": {
                                "query": q,
                                "fields": ["车型名称^15", "品牌^5", "基本信息_厂商^5"],
                                "type": "phrase_prefix",
                                "boost": 15.0,
                                "analyzer": "my_custom_search_analyzer"
                            }
                        },
                        {
                            "match_phrase_prefix": {
                                "车系名称": {
                                    "query": q,
                                    "boost": 10.0,
                                    "analyzer": "my_custom_search_analyzer"
                                }
                            }
                        },
                        {
                            "wildcard": {
                                "车系名称.keyword": {
                                    "value": f"*{q}*",
                                    "boost": 9.0,
                                    "case_insensitive": True
                                }
                            }
                        },
                        {
                            "wildcard": {
                                "车型名称.keyword": {
                                    "value": f"*{q}*",
                                    "boost": 8.0,
                                    "case_insensitive": True
                                }
                            }
                        },
                        {
                            "multi_match": {
                                "query": q,
                                "fields": ["车型名称", "车系名称", "品牌"],
                                "type": "most_fields",
                                "fuzziness": "AUTO",
                                "boost": 1.0
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            },
            "size": 20
        }

        response = es_client.search(index=INDEX_NAME, body=es_query)
        hits = [hit['_source'] for hit in response['hits']['hits']]
        return jsonify(hits)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/get-model-config', methods=['GET'])
def get_model_config():
    if not es_client:
        return jsonify({"error": "数据库服务未连接"}), 503
    try:
        model_id = request.args.get('model_id', type=str)
        series_name = request.args.get('series_name', type=str)

        if not model_id or not series_name:
            return jsonify({"error": "必须同时提供车型ID (model_id) 和车系名称 (series_name)"}), 400

        es_query = {
            "query": {"bool": {
                "must": [{"term": {"车型名称.keyword": model_id}}, {"term": {"车系名称.keyword": series_name}},
                         {"term": {"is_koubei_row": False}}]}},
            "size": 1
        }

        response = es_client.search(index=INDEX_NAME, body=es_query)
        hits = response['hits']['hits']

        if not hits:
            print(f"   -> (联合查询 model='{model_id}', series='{series_name}' 失败，尝试仅用 model_id 查询)")
            es_query_fallback = {
                "query": {
                    "bool": {"must": [{"term": {"车型名称.keyword": model_id}}, {"term": {"is_koubei_row": False}}]}},
                "size": 1
            }
            response = es_client.search(index=INDEX_NAME, body=es_query_fallback)
            hits = response['hits']['hits']

            if not hits:
                return jsonify({"error": f"数据库中未找到车型 '{model_id}' (尝试了联合查询和单独查询)"}), 404
            else:
                print(f"   -> (仅用 model_id 查询成功，返回第一个匹配项)")

        config_data = hits[0]['_source']
        return jsonify(config_data)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"获取车型配置时发生内部错误: {e}"}), 500


def _get_condensed_query(chat_history):
    if not chat_history: return ""
    last_user_message = chat_history[-1]
    last_user_question = last_user_message.get('content', '').strip()
    simple_compare_words = ["比较", "对比", "对比一下", "比吧"]
    is_simple_compare = any(last_user_question.startswith(word) for word in simple_compare_words)
    previous_ai_message = None
    if len(chat_history) > 1:
        for i in range(len(chat_history) - 2, -1, -1):
            if chat_history[i].get('role') == 'assistant':
                previous_ai_message = chat_history[i]
                break
    if is_simple_compare and previous_ai_message:
        previous_ai_response = previous_ai_message.get('content', '')
        mentioned_cars = set()
        pattern = r"(?:🚗|💰|🎯|✅|🏆|🥈|🥉)\s*\*{0,2}(.*?)(?:\*{0,2}|\s*（|\n)"
        matches = re.findall(pattern, previous_ai_response)
        for match in matches:
            car_name_match = re.match(r"([\w\s-]+(?:新能源)?(?:\s*[\w\d]+(?:款|型))?)",
                                      match.strip().replace("首选推荐：", "").replace("备选推荐：", "").replace(
                                          "超值之选：", "").replace("首推车型：", "").replace("备选推荐：", ""))
            if car_name_match:
                car_name = car_name_match.group(1).strip()
                if len(car_name) > 1 and "版" not in car_name[-2:] and "款" not in car_name[-2:]:
                    mentioned_cars.add(car_name)
        if mentioned_cars:
            extracted_names = " ".join(mentioned_cars)
            rewritten_query = f"对比 {extracted_names}"
            print(f"   -> (查询重写: 检测到极简对比提问，强制结合上一轮内容: {rewritten_query})")
            return rewritten_query
        else:
            print(f"   -> (查询重写: 检测到极简对比提问，但未能从上一轮提取车型，退回原始查询: {last_user_question})")
    comparison_keywords = ["哪个", "详细", "区别", "说说", "介绍下"]
    is_vague_follow_up = len(last_user_question) < 10 and any(kw in last_user_question for kw in comparison_keywords)
    if is_vague_follow_up and previous_ai_message:
        previous_ai_response = previous_ai_message.get('content', '')
        mentioned_cars = set()
        pattern = r"(?:🚗|💰|🎯|✅|🏆|🥈|🥉)\s*\*{0,2}(.*?)(?:\*{0,2}|\s*（|\n)"
        matches = re.findall(pattern, previous_ai_response)
        for match in matches:
            car_name_match = re.match(r"([\w\s-]+(?:新能源)?(?:\s*[\w\d]+(?:款|型))?)",
                                      match.strip().replace("首选推荐：", "").replace("备选推荐：", "").replace(
                                          "超值之选：", "").replace("首推车型：", "").replace("备选推荐：", ""))
            if car_name_match:
                car_name = car_name_match.group(1).strip()
                if len(car_name) > 1 and "版" not in car_name[-2:] and "款" not in car_name[-2:]:
                    mentioned_cars.add(car_name)
        if mentioned_cars:
            extracted_names = " ".join(mentioned_cars)
            rewritten_query = f"{extracted_names} {last_user_question}"
            print(f"   -> (查询重写: 检测到模糊后续提问，结合上一轮内容: {rewritten_query})")
            return rewritten_query
        else:
            print(f"   -> (查询重写: 检测到模糊后续提问，但未能从上一轮提取车型，退回原始查询: {last_user_question})")
    if not llm_client:
        if len(chat_history) > 2:
            for i in range(len(chat_history) - 3, -1, -1):
                if chat_history[i].get('role') == 'user':
                    prev_user_q = chat_history[i].get('content', '')
                    merged_q = f"{prev_user_q} {last_user_question}"
                    print(f"   -> (查询重写: 无LLM，简单合并: {merged_q})")
                    return merged_q
        print(f"   -> (查询重写: 无LLM，使用原始查询: {last_user_question})")
        return last_user_question
    history_str = ""
    for msg in chat_history:
        if msg.get('role') == 'assistant' and "请告诉我您的购车需求" in msg.get('content', ''):
            continue
        role = "用户" if msg.get('role') == 'user' else "AI"
        history_str += f"{role}: {msg.get('content')}\n"

    is_seemingly_complete = (
            len(chat_history) <= 2 or \
            ("万" in last_user_question and (
                    "车" in last_user_question or "SUV" in last_user_question or "MPV" in last_user_question)) or \
            (("对比" in last_user_question or "比较" in last_user_question) and len(last_user_question) > 5)
    )
    if is_seemingly_complete and not is_vague_follow_up and not is_simple_compare:
        print(f"   -> (查询重写: 看似完整查询，跳过LLM，使用原始查询: {last_user_question})")
        return last_user_question

    system_prompt = """你是一个查询重写助手。你的唯一任务是阅读聊天记录和用户的最新问题，
然后将最新的问题改写成一个独立的、完整的查询，以便于在数据库中搜索。
**规则:**
1. 保持原始查询中的所有关键约束（如价格、品牌、车型、动力类型、车身类型等）。
2. 从聊天记录中继承上下文（如 "20万左右", "SUV"），并将其与最新问题（如 "燃油的呢"）合并。
3. 只返回改写后的查询，不要有任何解释。
**示例 1:**
聊天记录:
用户: 20万左右的suv
AI: 好的，我为您找到...
用户: 燃油的呢
改写后的查询: 20万左右的燃油suv
**示例 2:**
聊天记录:
用户: 推荐几款奥迪
AI: 好的，您对价格...
用户: 50万以内，轿车
改写后的查询: 50万以内的奥迪轿车
"""
    user_prompt = f"聊天记录:\n{history_str}\n改写后的查询:"
    try:
        response = llm_client.chat.completions.create(
            model=DEEPSEEK_MODEL_NAME,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0,
            max_tokens=100
        )
        condensed_query = response.choices[0].message.content.strip()
        if not condensed_query:
            print(f"   -> (查询重写: LLM 返回空，退回原始查询: {last_user_question})")
            return last_user_question
        if condensed_query in simple_compare_words:
            print(f"   -> (查询重写: LLM仅返回比较词，可能未理解上下文，退回原始查询: {last_user_question})")
            return last_user_question
        print(f"   -> (查询重写: LLM改写结果: {condensed_query})")
        return condensed_query
    except Exception as e:
        print(f"   -> (查询重写: LLM调用失败: {e}，退回原始查询: {last_user_question})")
        return last_user_question


def create_parser_prompt(user_prompt):
    feature_field_mapping_docs = ""
    if FEATURE_MAPPING:
        feature_field_mapping_docs += "**特性->字段映射表 (用于查找字段):**\n"
        for feature, mapping in FEATURE_MAPPING.items():
            fields_str = ", ".join(mapping.get("fields", []))
            aliases = [feature]
            for term in mapping.get("search_terms", []):
                if term not in ["●", "○", "标配", "选配", "是", "有"] and len(term) > 1 and term != feature:
                    aliases.append(term)
            aliases_str = ", ".join(list(set(aliases)))
            feature_field_mapping_docs += f"* 用户说 '{aliases_str}' -> `fields`: [{fields_str}]\n"
        feature_field_mapping_docs += "\n"
    else:
        feature_field_mapping_docs = """
**特性->字段映射表 (回退):**
* "四驱" -> `fields`: ["底盘转向_驱动形式", "车型名称.keyword"]
* "矩阵大灯" -> `fields`: ["灯光功能_灯光特色功能", "灯光功能_远光灯光源","灯光功能_近光灯光源"]
* "座椅通风" -> `fields`: ["座椅配置_第一排座椅功能", "座椅配置_第二排座椅功能"]
"""
    return f"""
你是一个专业的汽车搜索引擎查询分析师。你的任务是分析用户的自然语言输入，并将其转换为一个结构化的JSON对象，以便于后续的数据库查询。
**JSON结构定义:**
{{
  "brand": ["品牌名"] | null,
  "manufacturer": ["厂商名"] | null,
  "series": ["车系名"] | null,
  "price_min": (数字, 单位:万) | null,
  "price_max": (数字, 单位:万) | null,
  "power_type": ["纯电", ...] | null,
  "body_type": ["SUV", ...] | null,
  "feature_filters": [
    {{ "query": "用户意图核心词", "fields": ["数据库字段名1", ...] }}
  ] | null,
  "keywords_for_llm": "用户原始提问的精简版"
}}
**解析规则:**
1.  **[!] 提取核心车辆类型 (必须优先处理!)**:
    * **动力类型 (power_type)**:
        * 从用户输入中识别明确的动力类型，如 "燃油", "纯电", "插电混动", "增程式" 等。
        * **[!] 特殊映射**: 如果用户明确提到 **"新能源"** 并且没有指定更具体的类型（如纯电/插混），**必须**将 `power_type` 设置为 `["纯电", "插电混动", "增程式"]`。
        * 如果用户同时提到了 "新能源" 和具体类型（如 "新能源纯电"），则优先使用具体类型（`["纯电"]`）。
        * 如果提到了明确类型，**必须**填入 `power_type` 列表。
    * **车身类型 (body_type)**: 从用户输入中识别明确的车身类型，如 "SUV", "轿车", "MPV" 等。如果提到，**必须**填入 `body_type` 列表。
2.  **品牌 (brand) / 厂商 (manufacturer) / 车系 (series) 识别 (重要!)**:
    * **目标**: 正确区分并提取 `brand`, `manufacturer`, `series`。
    * **车系识别**: 优先识别**车系名** (例如 "Model 3", "Model Y", "A4L", "5系", "问界M7", "智界R7")。如果识别到，填入 `series` 列表。
    * **品牌/厂商识别**: 同时识别**品牌名** (例如 "特斯拉", "宝马", "奥迪", "鸿蒙智行") 或**厂商名** (例如 "问界", "智界", "享界")。
    * **组合处理 (关键!)**:
        * **"特斯拉Model 3"**: **必须**解析为 `brand: ["特斯拉"], series: ["Model 3"]`。
        * **"问界M7"**: **必须**解析为 `manufacturer: ["问界"], series: ["问界M7"], brand: ["鸿蒙智行"]` (因为问界是厂商，隶属鸿蒙智行品牌，车系是问界M7)。
        * **"奥迪A4L"**: **必须**解析为 `brand: ["奥迪"], series: ["A4L"]` (A4L是车系)。
        * **"宝马5系"**: **必须**解析为 `brand: ["宝马"], series: ["5系"]`。
    * **单独提及**:
        * **"特斯拉"**: 解析为 `brand: ["特斯拉"]`。
        * **"问界"**: 解析为 `manufacturer: ["问界"], brand: ["鸿蒙智行"]`。
        * **"鸿蒙智行"**: 解析为 `brand: ["鸿蒙智行"]`。
        * **"Model 3"**: 解析为 `series: ["Model 3"]`。
        * **"M7"**: 解析为 `series: ["问界M7"]` (需要映射)。
    * **车型号映射**: 将常见的简写或型号（如 "M7", "3", "530Li", "A4L"）映射到**完整车系名**填入 `series` (例如 "M7" -> `series: ["问界M7"]`, "3" (如果上下文是特斯拉) -> `series: ["Model 3"]`, "530Li" -> `series: ["5系"]`)。
    * **优先级**: 以最精确的识别（通常是车系）为主。如果识别出 `series`，`brand` 和 `manufacturer` 作为补充。
3.  **价格**:
    * "XX万左右" -> 必须解析为一个区间，例如 "30万左右" 解析为 `price_min: 27, price_max: 33` (上下浮动10%)。
    * "XX到YY万" -> 解析为 `price_min: XX, price_max: YY`。
    * "XX万以内/以下" -> 解析为 `price_max: XX`。
    * "XX万以上" -> 解析为 `price_min: XX`。
    * 正常解析数字。
4.  **特性过滤器 (feature_filters)**:
    * 识别用户提到的核心配置或特性。**必须**忽略 "标配"、"选配"、"带不带"、"有没有"、"是否" 等修饰词，只提取**核心特性词**（例如 "座椅通风", "四驱", "矩阵大灯"）作为 `query` 的值。
    * 根据**下面的映射表**，找到这个核心特性词对应的**数据库字段**，填入 `fields` 列表。
    {feature_field_mapping_docs}
5.  **keywords_for_llm**: 用户原始提问精简版。
6.  **只返回JSON**。
---
**示例:**
- **输入**: "对比一下奥迪A4L和宝马530Li"
- **输出**:
{{
  "brand": ["奥迪", "宝马"],
  "manufacturer": null,
  "series": ["A4L", "5系"],
  "price_min": null,
  "price_max": null,
  "power_type": null,
  "body_type": null,
  "feature_filters": null,
  "keywords_for_llm": "对比奥迪A4L和宝马530Li"
}}
---
请严格按照上述规则，解析以下用户输入：
"{user_prompt}"
"""


def _create_hybrid_query(names_list, keyword_field, text_field):
    if not names_list: return None
    hybrid_should_clauses = []
    for name in names_list:
        if not name: continue
        hybrid_should_clauses.append(
            {"prefix": {keyword_field: {"value": name, "boost": 10.0, "case_insensitive": True}}})
        hybrid_should_clauses.append({"match": {text_field: {"query": name, "boost": 5.0}}})
    if not hybrid_should_clauses: return None
    return {"bool": {"should": hybrid_should_clauses, "minimum_should_match": 1}}


def clean_es_result(doc):
    cleaned_doc = {}
    if not isinstance(doc, dict):
        return doc
    for key, value in doc.items():
        new_key = key.replace(".keyword", "")
        if isinstance(value, dict):
            cleaned_doc[new_key] = clean_es_result(value)
        elif isinstance(value, list):
            cleaned_doc[new_key] = [clean_es_result(item) if isinstance(item, dict) else item for item in value]
        else:
            cleaned_doc[new_key] = value
    return cleaned_doc


@app.route('/ai_chat', methods=['POST'])
def ai_chat():
    if not llm_client: return jsonify({"error": "AI服务未配置或不可用"}), 503
    if not es_client: return jsonify({"error": "数据库服务未连接"}), 503
    data = request.json
    chat_history = data.get('history', [])
    if not chat_history:
        return jsonify({"error": "聊天内容不能为空"}), 400
    current_prompt = chat_history[-1].get('content', '')
    if not current_prompt:
        return jsonify({"error": "最新提问不能为空"}), 400
    known_series = data.get('known_series')
    known_model = data.get('known_model')
    has_known_series = bool(known_series and known_series.strip())
    has_known_model = bool(known_model and known_model.strip())
    is_first_message = len(chat_history) == 1
    # 识别模糊的对比或后续提问 (例如: "和他比", "和5系比", "怎么样?", "呢?")
    vague_starters = ["和他", "和它", "对比", "比较", "比一比", "跟它", "跟", "那"]
    vague_enders = ["呢", "呢？", "咋样", "咋样？", "怎么样", "怎么样？"]

    is_vague_comparison = any(current_prompt.startswith(term) for term in vague_starters)
    is_vague_follow_up = any(current_prompt.endswith(term) for term in vague_enders) and len(
        current_prompt) < 25

    if (has_known_series or has_known_model) and is_first_message and (is_vague_comparison or is_vague_follow_up):
        context_to_add = known_model if has_known_model else known_series

        chat_history.insert(0, {"role": "user", "content": context_to_add})
        print(f"   -> (AI Chat: 检测到模糊提问，自动注入上下文 '{context_to_add}')")

    print(f"\n\n--- [AI CHAT DEBUG] ---")
    print(f"1. 接收到聊天记录，最新提问: {current_prompt}")
    if has_known_series: print(f"   -> 已知车系 (Known Series): {known_series}")
    if has_known_model: print(f"   -> 已知车型 (Known Model): {known_model}")
    try:
        condensed_query = _get_condensed_query(chat_history)
        applied_feature_filter = False
        requested_fields_set = set()
        parser_prompt_text = create_parser_prompt(condensed_query)
        parsed_params = {}
        try:
            llm_response_parser = llm_client.chat.completions.create(
                model=DEEPSEEK_MODEL_NAME,
                messages=[
                    {"role": "system", "content": "你是一个只返回JSON的查询解析器。"},
                    {"role": "user", "content": parser_prompt_text}
                ],
                temperature=0.0
            )
            response_text = llm_response_parser.choices[0].message.content
            match = re.search(r"\{.*\}", response_text, re.DOTALL)
            if not match: raise ValueError("AI未能返回有效的JSON格式")
            parsed_params = json.loads(match.group(0))
            print(f"2. AI意图解析 (JSON): \n{json.dumps(parsed_params, indent=2, ensure_ascii=False)}")
        except Exception as e:
            print(f"2. AI意图解析失败: {e}。退回到关键词匹配。")
            traceback.print_exc()
            parsed_params = {"keywords_for_llm": condensed_query}
        param_must_conditions = [{"term": {"is_koubei_row": False}}]
        param_should_conditions = []
        all_series_for_query = []
        if has_known_series:
            param_must_conditions.append({"term": {"车系名称.keyword": known_series}})
            print(f"   -> (强制范围: 精确匹配 known_series = {known_series})")
            all_series_for_query.append(known_series)
            if has_known_model:
                param_must_conditions.append({"term": {"车型名称.keyword": known_model}})
                print(f"   -> (强制范围: 精确匹配 known_model = {known_model})")
        ai_parsed_series = parsed_params.get("series", [])
        ai_parsed_brands = parsed_params.get("brand", [])
        ai_parsed_mfgs = parsed_params.get("manufacturer", [])
        is_comparison = has_known_series and ai_parsed_series and any(
            s.lower() != known_series.lower() for s in ai_parsed_series)
        if is_comparison:
            comparison_targets = [s for s in ai_parsed_series if s.lower() != known_series.lower()]
            if comparison_targets:
                all_series_for_query.extend(comparison_targets)
                comparison_query = _create_hybrid_query(comparison_targets, "车系名称.keyword", "车系名称")
                param_must_conditions = [
                    cond for cond in param_must_conditions if (
                            cond.get("term", {}).get("车系名称.keyword") != known_series and
                            (not known_model or cond.get("term", {}).get("车型名称.keyword") != known_model)
                    )
                ]
                comparison_should_clauses = []
                if has_known_model:
                    model_query = _create_hybrid_query([known_model], "车型名称.keyword", "车型名称")
                    if model_query:
                        comparison_should_clauses.append(model_query)
                if has_known_series:
                    series_query = _create_hybrid_query([known_series], "车系名称.keyword", "车系名称")
                    if series_query:
                        comparison_should_clauses.append(series_query)
                if comparison_query:
                    comparison_should_clauses.append(comparison_query)
                if comparison_should_clauses:
                    param_must_conditions.append({
                        "bool": {
                            "should": comparison_should_clauses,
                            "minimum_should_match": 1
                        }
                    })
                    print(f"   -> (对比范围: 已重构查询以包含 {known_series}, {known_model} 和 {comparison_targets})")
        elif not has_known_series:
            print(f"   -> (无上下文，使用AI解析结果进行模糊查找)")
            if ai_parsed_series:
                all_series_for_query = ai_parsed_series
                hybrid_series_query = _create_hybrid_query(ai_parsed_series, "车系名称.keyword", "车系名称")
                if hybrid_series_query:
                    param_must_conditions.append(hybrid_series_query)
                    print(f"   -> (添加 AI 解析的车系(hybrid)条件: {ai_parsed_series})")
            elif ai_parsed_brands:
                hybrid_brand_query = _create_hybrid_query(ai_parsed_brands, "品牌.keyword", "品牌")
                if hybrid_brand_query:
                    param_must_conditions.append(hybrid_brand_query)
                    print(f"   -> (添加 AI 解析的品牌(hybrid)条件: {ai_parsed_brands})")
            elif ai_parsed_mfgs:
                hybrid_mfg_query = _create_hybrid_query(ai_parsed_mfgs, "基本信息_厂商.keyword", "基本信息_厂商")
                if hybrid_mfg_query:
                    param_must_conditions.append(hybrid_mfg_query)
                    print(f"   -> (添加 AI 解析的厂商(hybrid)条件: {ai_parsed_mfgs})")
        feature_filters = parsed_params.get("feature_filters", [])
        if feature_filters:
            feature_should_clauses = []
            for f_filter in feature_filters:
                user_intent_query = f_filter.get("query")
                ai_suggested_fields = f_filter.get("fields", [])
                search_terms = []
                target_fields = ai_suggested_fields
                if FEATURE_MAPPING and user_intent_query and user_intent_query in FEATURE_MAPPING:
                    mapping = FEATURE_MAPPING[user_intent_query]
                    base_search_terms = mapping.get("search_terms", [user_intent_query])
                    search_terms = list(set(base_search_terms + ["标配", "●", "选配", "○"]))
                    target_fields = mapping.get("fields", ai_suggested_fields)
                    print_prefix = f"特性过滤器(映射): '{user_intent_query}'"
                elif user_intent_query and ai_suggested_fields:
                    search_terms = [user_intent_query, "标配", "●", "选配", "○"]
                    target_fields = ai_suggested_fields
                    print_prefix = f"特性过滤器(回退): '{user_intent_query}'"
                else:
                    print(f"   -> (警告: AI 解析的特性过滤器无效: {f_filter})")
                    continue
                expanded_target_fields = set(target_fields)
                expanded_target_fields.add("车型名称")
                expanded_target_fields.add("车系名称")
                if expanded_target_fields:
                    requested_fields_set.update(expanded_target_fields)
                if search_terms and expanded_target_fields:
                    print(f"   -> (特性搜索词 (已扩展): {search_terms})")
                    wildcard_should_clauses_for_feature = []
                    for field in expanded_target_fields:
                        text_field = field.replace(".keyword", "")
                        keyword_field = field if ".keyword" in field else f"{field}.keyword"
                        for term_val in search_terms:
                            wildcard_should_clauses_for_feature.append({
                                "wildcard": {
                                    keyword_field: {"value": f"*{term_val}*", "case_insensitive": True, "boost": 2.0}}
                            })
                            wildcard_should_clauses_for_feature.append({
                                "match": {text_field: {"query": term_val, "boost": 1.0}}
                            })
                    if wildcard_should_clauses_for_feature:
                        feature_should_clauses.append({
                            "bool": {
                                "should": wildcard_should_clauses_for_feature,
                                "minimum_should_match": 1
                            }
                        })
                        print(
                            f"   -> ({print_prefix} -> 添加特性匹配(should): {search_terms} in {list(expanded_target_fields)})")
                        applied_feature_filter = True
            if feature_should_clauses:
                param_should_conditions.extend(feature_should_clauses)
        price_min_filter = parsed_params.get("price_min")
        price_max_filter = parsed_params.get("price_max")
        if price_min_filter or price_max_filter:
            price_query = {}
            if price_min_filter: price_query["gte"] = price_min_filter
            if price_max_filter: price_query["lte"] = price_max_filter
            param_must_conditions.append({"range": {"price_numeric": price_query}})
            print(f"   -> (添加价格条件(must): {price_query})")
        if parsed_params.get("power_type"):
            param_must_conditions.append({"terms": {"动力类型": parsed_params.get("power_type")}})
            print(f"   -> (添加动力条件(must): {parsed_params.get('power_type')})")
        if parsed_params.get("body_type"):
            param_must_conditions.append({"terms": {"车身类型": parsed_params.get("body_type")}})
            print(f"   -> (添加车身条件(must): {parsed_params.get('body_type')})")
        keywords_for_llm = parsed_params.get("keywords_for_llm", "")
        if keywords_for_llm and not applied_feature_filter and not is_comparison:
            param_should_conditions.append(
                {"multi_match": {
                    "query": keywords_for_llm,
                    "fields": ["品牌", "车系名称", "车型名称^2"],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                    "boost": 1.0
                }}
            )
            print(f"   -> (添加 LLM 关键词(should): {keywords_for_llm})")
        elif is_comparison:
            print(f"   -> (对比查询，已跳过 LLM 关键词(should) 以防止排名污染)")
        min_should_match = 0
        if param_should_conditions:
            print(f"   -> (有 {len(param_should_conditions)} 个 should 条件，仅用于提分，minimum_should_match=0)")
        else:
            print(f"   -> (无 should 条件，minimum_should_match=0)")
        price_functions = []
        if price_max_filter and not price_min_filter:
            price_functions.append({"gauss": {
                "price_numeric": {"origin": price_max_filter, "scale": price_max_filter / 2.5,
                                  "offset": price_max_filter / 5, "decay": 0.5}}, "weight": 2})
            print(f"   -> (价格优化：提升接近 {price_max_filter}万 的车型得分)")
        elif price_min_filter and not price_max_filter:
            price_functions.append({"gauss": {
                "price_numeric": {"origin": price_min_filter, "scale": price_min_filter * 2,
                                  "offset": price_min_filter / 5, "decay": 0.5}}, "weight": 2})
            print(f"   -> (价格优化：提升高于 {price_min_filter}万 的车型得分)")
        elif price_min_filter and price_max_filter:
            origin_price = (price_min_filter + price_max_filter) / 2
            scale_price = (
                                  price_max_filter - price_min_filter) / 2 if price_max_filter > price_min_filter else price_min_filter / 2
            price_functions.append({"gauss": {"price_numeric": {"origin": origin_price, "scale": max(scale_price, 5),
                                                                "offset": max(scale_price, 5) / 2, "decay": 0.5}},
                                    "weight": 3})
            print(f"   -> (价格优化：提升 {price_min_filter}-{price_max_filter}万 范围的车型得分)")
        base_bool_query = {"bool": {"must": param_must_conditions, "should": param_should_conditions,
                                    "minimum_should_match": min_should_match}}
        fetch_size = 60
        if price_functions:
            param_query = {
                "query": {
                    "function_score": {
                        "query": base_bool_query,
                        "functions": price_functions,
                        "score_mode": "multiply",
                        "boost_mode": "multiply"
                    }
                },
                "size": fetch_size
            }
            print(f"   -> (使用 function_score (multiply 模式) 进行价格提分)")
        else:
            param_query = {"query": base_bool_query, "size": fetch_size}
            print(f"   -> (使用基础 bool 查询)")
        print(f"3. 参数库ES查询 (Query): \n{json.dumps(param_query, indent=2, ensure_ascii=False)}")
        param_response = es_client.search(index=INDEX_NAME, body=param_query)
        raw_param_results = [hit['_source'] for hit in param_response['hits']['hits']]
        param_results = [clean_es_result(doc) for doc in raw_param_results]
        print(f"4. 参数库ES结果: 召回 {len(param_results)} 个车型 (已清理)")
        target_series_for_review = []
        if all_series_for_query:
            target_series_for_review = list(set(all_series_for_query))
            print(f"   -> (口碑查询目标车系: {target_series_for_review})")
        else:
            found_series_names = list(set([p.get('车系名称') for p in param_results if p.get('车系名称')]))
            if found_series_names:
                target_series_for_review = found_series_names
                print(f"   -> (口碑基于参数库结果车系: {found_series_names})")
        review_results_raw = []
        if target_series_for_review:
            review_must_conditions = [{"term": {"is_koubei_row": True}}]
            review_scope_should = []
            if has_known_series and known_series in target_series_for_review:
                series_query = _create_hybrid_query([known_series], "车系名称.keyword", "车系名称")
                if series_query:
                    review_scope_should.append(series_query)
            other_targets = [s for s in target_series_for_review if s != known_series]
            if other_targets:
                hybrid_other_query = _create_hybrid_query(other_targets, "车系名称.keyword", "车系名称")
                if hybrid_other_query:
                    review_scope_should.append(hybrid_other_query)
            if review_scope_should:
                review_must_conditions.append({"bool": {"should": review_scope_should, "minimum_should_match": 1}})
            review_should_conditions_features = []
            if feature_filters:
                for f_filter in feature_filters:
                    user_intent_query = f_filter.get("query")
                    search_terms_for_review = []
                    if FEATURE_MAPPING and user_intent_query and user_intent_query in FEATURE_MAPPING:
                        search_terms_for_review = FEATURE_MAPPING[user_intent_query].get("search_terms",
                                                                                         [user_intent_query])
                    elif user_intent_query:
                        search_terms_for_review = [user_intent_query]
                    if search_terms_for_review:
                        extended_review_terms = " ".join(
                            list(set(search_terms_for_review + ["标配", "●", "选配", "○"])))
                        review_should_conditions_features.append(
                            {"match": {"所有评价": {"query": extended_review_terms, "boost": 10}}}
                        )
            review_query = {
                "query": {"bool": {"must": review_must_conditions, "should": review_should_conditions_features,
                                   "minimum_should_match": 0}},
                "size": 20
            }
            print(f"5. 口碑库ES查询 (Query): \n{json.dumps(review_query, indent=2, ensure_ascii=False)}")
            review_response = es_client.search(index=INDEX_NAME, body=review_query)
            review_results_raw = [hit['_source'] for hit in review_response['hits']['hits']]
            print(f"6. 口碑库ES结果: 找到了 {len(review_results_raw)} 条相关口碑")
        else:
            print("5. 未确定目标车系，跳过口碑库精确查询。")
        review_results = [clean_es_result(doc) for doc in review_results_raw]
        context_for_llm = ""
        context_for_llm += "--- 车辆参数资料库 (供你推荐或对比的车型) ---\n"
        raw_recommended_cars_map = {}
        if param_results:
            final_models_for_recommendation = param_results
            for i, res in enumerate(final_models_for_recommendation):
                model_id_for_llm = str(i + 1)
                model_marker = ""
                if has_known_model and res.get('车型名称') == known_model:
                    model_marker = "【用户当前关注车型资料】"
                context_for_llm += f"【ID: {model_id_for_llm}】{model_marker}\n"
                context_for_llm += f"  - 厂商: {res.get('基本信息_厂商', 'N/A')}\n"
                context_for_llm += f"  - 车系: {res.get('车系名称', 'N/A')}\n"
                context_for_llm += f"  - 车型: {res.get('车型名称', 'N/A')}\n"
                context_for_llm += f"  - 动力: {res.get('动力类型', 'N/A')}\n"
                context_for_llm += f"  - 驱动形式: {res.get('底盘转向_驱动形式', 'N/A')}\n"
                context_for_llm += f"  - 价格(万): {res.get('price_numeric', 'N/A')}\n"
                context_for_llm += "  - 关键配置:\n"
                if not requested_fields_set:
                    context_for_llm += "    - (未指定特定配置)\n"
                else:
                    found_config = False
                    cleaned_requested_fields = {f.replace(".keyword", "") for f in requested_fields_set}
                    cleaned_requested_fields.add("车型名称")
                    cleaned_requested_fields.add("车系名称")
                    displayed_configs = set()
                    for field_name in sorted(list(cleaned_requested_fields)):
                        field_value = res.get(field_name, "—")
                        display_field_name = re.sub(
                            r"^(?:基本信息|车身|动力系统|发动机|电机|电池/补能|变速箱|底盘转向|车轮制动|主动安全|辅助/操控配置|外部配置|内部配置|座椅配置|多媒体配置|智能互联|灯光配置|玻璃/后视镜|空调/冰箱)_",
                            "", field_name)
                        if display_field_name not in displayed_configs:
                            context_for_llm += f"    - {display_field_name}: {field_value}\n"
                            displayed_configs.add(display_field_name)
                            if field_value not in ["—", None, ""]:
                                found_config = True
                    if not found_config:
                        context_for_llm += "    - (未找到您关注的配置信息)\n"
                context_for_llm += "\n"
                car_info_for_rec = {
                    "type": "model",
                    "name": res.get('车型名称', 'N/A'),
                    "series_name": res.get('车系名称', 'N/A'),
                    "price": res.get('基本信息_厂商指导价', 'N/A')
                }
                if car_info_for_rec["name"] != 'N/A' and car_info_for_rec["series_name"] != 'N/A':
                    raw_recommended_cars_map[model_id_for_llm] = car_info_for_rec
        else:
            context_for_llm += "在我的车辆参数库中没有找到与您需求匹配的车型。\n\n"
        context_for_llm += "--- 用户真实口碑资料库 (供你分析的评价) ---\n"
        if review_results:
            for i, result in enumerate(review_results):
                series_name_review = result.get('车系名称', '未知车系')
                review_text = result.get('所有评价', '暂无具体评价')
                user_model_match = re.search(r"\[用户填写车型:\s*(.*?)\]", review_text)
                user_model_review = user_model_match.group(1).strip() if user_model_match else '未知具体车型'
                review_content = re.sub(r"\[用户填写车型:.*?\]", "", review_text).strip()
                context_for_llm += f"【口碑资料{i + 1}: {series_name_review} (车主车型: {user_model_review})】\n"
                context_for_llm += f"  - 综合评分: {result.get('平均评分', 'N/A')}\n"
                context_for_llm += f"  - 用户评价详情: \"{review_content}\"\n\n"
        else:
            context_for_llm += "没有找到与您需求直接相关的真实用户口碑。\n\n"
        print(f"7. 最终发送给AI的上下文 (节选):\n{context_for_llm[:1000]}...")
        history_for_llm = []
        for msg in chat_history[:-1]:
            if msg.get('role') in ('user', 'assistant'):
                if not (msg.get('role') == 'assistant' and "请告诉我您的购车需求" in msg.get('content', '')):
                    history_for_llm.append(msg)
        final_query_for_llm = parsed_params.get("keywords_for_llm", current_prompt)
        system_prompt = f"""
你是一位资深、专业且风趣的汽车推荐官或对比分析师。
你的任务是严格根据我提供的【车辆参数资料库】和【用户真实口碑资料库】来回答用户的最新提问。

**【【【输出格式要求】】】**
你的回答**必须**是一个**单独的JSON对象**，包含以下两个键：
1.  `"response_text"` (string): 你给用户的自然语言回复。
2.  `"recommended_ids"` (list[string]): 一个字符串列表，包含你在 `response_text` 中提到或推荐的**所有**车型的【ID】。

**示例输出：**
{{
  "response_text": "您好！根据您的需求，我推荐【ID: 1】奥迪A6L。一位【车主车型: 2024款 A6L】的车主提到它...。备选方案可以考虑【ID: 3】宝马5系。",
  "recommended_ids": ["1", "3"]
}}

**【【【回复规则 (必须严格遵守)】】】**
1.  **ID引用 (内部)**: 当你在 `response_text` 中提到资料库中的任何车型时，**必须**使用 `【ID: X】` 的格式来引用它 (X是资料库中的ID)。
2.  **ID填充 (内部)**: 凡是在 `response_text` 中被 `【ID: X】` 引用的车型，其 ID (例如 "1", "3") **必须**被收集到 `recommended_ids` 列表中。

3.  **【【【新：推荐结构】】】**:
    * 如果是**推荐**任务（非对比），请**必须**严格按照以下结构回复：
        * **(1) 首选推荐 (1-2款)**: 挑选 1-2 款最匹配的车型 (【ID: X】)，使用 **"🏆 首选推荐："** 或 **"🥈 次选推荐："** 这样的标题，并详细分析。
        * **(2) 备选方案 (最多 3-4款)**: 挑选 3-4 款其他符合条件的车型 (【ID: Y】)，使用 **"✅ 备选方案："** 标题，并简要说明。
        * 总推荐数**不要超过6款**。
    * 如果是**对比**任务，请只对比用户明确提到的车型，无需使用上述结构。

4.  **【【【新：口碑引用】】】**:
    * 当你引用【用户真实口碑资料库】时，**必须**在 `response_text` 中明确提及该口碑来自哪个**【车主车型】** (该信息在 `【口碑资料X: ... (车主车型: Y)】` 中提供)。
    * *示例*: "一位【车主车型: 2023款 530Li】的车主提到..." 或 "根据【车主车型: 问界M7 智驾版】的口碑..."
    * **必须**结合口碑分析优缺点。

5.  **禁止杜撰**: 严禁提及任何【车辆参数资料库】中未包含的车辆信息（除非是根据规则6进行解释）。
6.  **资料库为空/不完全匹配**:
    * 如果【车辆参数资料K】为空，请在 `response_text` 中诚恳告知用户找不到满足*所有*条件的车型，此时 `recommended_ids` 必须为空列表 `[]`。
    * 如果召回的车型**部分满足**条件，请在 `response_text` 中**明确指出**。
7.  **特性查询 (标配/选配)**: 如果是查询特定特性，必须仔细检查【关键配置】的文本内容，判断是“标配”还是“选配”并明确说明。
"""
        user_prompt_parts = []
        if has_known_model and has_known_series:
            user_prompt_parts.append(
                f"--- 用户当前关注车型 ---\n车系: {known_series}\n车型: {known_model}\n(请在分析时优先关注资料库中标记为【用户当前关注车型资料】的车辆)\n---------------------")
        elif has_known_series:
            user_prompt_parts.append(
                f"--- 用户当前关注车系 ---\n车系: {known_series}\n(请在分析时优先关注该车系)\n---------------------")
        user_prompt_parts.append(
            f"--- 聊天记录上下文 ---\n{json.dumps(history_for_llm, ensure_ascii=False)}\n---------------------")
        user_prompt_parts.append(f"--- 资料库 (你的唯一信息来源) ---\n{context_for_llm}\n---------------------")
        user_prompt_parts.append(f"--- 用户的最新提问 ---\n\"{final_query_for_llm}\"")
        user_prompt_parts.append("\n请严格按照系统指令的JSON格式返回你的分析。")
        final_user_prompt = "\n".join(user_prompt_parts)
        messages_to_send = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": final_user_prompt}
        ]
        llm_response = llm_client.chat.completions.create(
            model=DEEPSEEK_MODEL_NAME,
            messages=messages_to_send,
            temperature=0.3,
            response_format={"type": "json_object"}
        )
        ai_response_content = llm_response.choices[0].message.content if llm_response.choices else "{}"
        print(f"8. AI已成功返回 (原始JSON): {ai_response_content[:300]}...")
        try:
            clean_json_str = re.sub(r"^\s*```json\s*|\s*```\s*$", "", ai_response_content, flags=re.DOTALL).strip()
            ai_data = json.loads(clean_json_str)
            ai_response_text_raw = ai_data.get("response_text", "抱歉，AI推荐服务暂时遇到问题，请稍后再试。")
            ai_recommended_ids = ai_data.get("recommended_ids", [])

            ai_response_text = re.sub(r"【ID:\s*\d+】", "", ai_response_text_raw).strip()
            ai_response_text = re.sub(r"\s*【ID:\s*\d+】\s*", " ", ai_response_text).strip()
        except json.JSONDecodeError as e:
            print(f"   -> (严重错误: AI未返回标准JSON: {e})")
            print(f"   -> (原始回复): {ai_response_content}")
            ai_response_text = ai_response_content if ai_response_content.strip() else "抱歉，AI未能正确处理您的请求。"
            ai_recommended_ids = []
        final_recommended_cars_list = []
        if ai_recommended_ids:
            print(f"   -> (精确过滤：AI 推荐了 {len(ai_recommended_ids)} 个ID: {ai_recommended_ids})")
            for car_id in ai_recommended_ids:
                car_data = raw_recommended_cars_map.get(str(car_id))
                if car_data:
                    final_recommended_cars_list.append(car_data)
                else:
                    print(f"   -> (警告: AI 推荐了不存在的 ID: {car_id})")
        else:
            print(f"   -> (精确过滤：AI 未推荐任何车型ID)")
        return jsonify({
            "response_text": ai_response_text,
            "recommended_cars": final_recommended_cars_list
        })
    except Exception as e:
        print(f"--- [AI CHAT ERROR] ---")
        traceback.print_exc()
        return jsonify({"error": f"AI聊天时发生内部错误: {e}"}), 500


@app.route('/get-review-summary', methods=['GET'])
def get_review_summary():
    if not llm_client: return jsonify({"error": "AI服务未配置或不可用"}), 503
    if not es_client: return jsonify({"error": "数据库服务未连接"}), 503

    series_name = request.args.get('series_name', type=str)
    if not series_name:
        return jsonify({"error": "必须提供车系名称"}), 400

    filters_str = request.args.get('filters', '{}')
    filter_context = ""
    try:
        filters = json.loads(filters_str)
        filter_parts = []
        if filters.get('power_type') and filters['power_type'] != '不限': filter_parts.append(filters['power_type'])
        if filters.get('body_type') and filters['body_type'] != '不限': filter_parts.append(filters['body_type'])
        if filters.get('segment') and filters['segment'] != '不限': filter_parts.append(filters['segment'])
        price_min = filters.get('price_min', 0)
        price_max = filters.get('price_max', 0)
        if price_min > 0 and price_max > 0:
            filter_parts.append(f"{price_min}-{price_max}万")
        elif price_min > 0:
            filter_parts.append(f"{price_min}万以上")
        elif price_max > 0:
            filter_parts.append(f"{price_max}万以内")
        filter_context = ", ".join(filter_parts)
    except Exception as e:
        print(f"解析AI总结过滤器失败: {e}")

    print(f"\n--- [AI SUMMARY DEBUG] ---")
    print(f"1. 开始为 {series_name} 生成口碑总结...")
    print(f"   -> 过滤器上下文: {filter_context}")
    try:
        review_query = {
            "query": {
                "bool": {"must": [{"term": {"is_koubei_row": True}}, {"term": {"车系名称.keyword": series_name}}]}},
            "size": 1
        }
        review_response = es_client.search(index=INDEX_NAME, body=review_query)
        review_results_raw = [hit['_source'] for hit in review_response['hits']['hits']]

        if not review_results_raw:
            print(f"2. 未找到 {series_name} 的口碑数据。")
            return jsonify({"error": "暂无该车系的用户口碑数据。"}), 404

        review_doc = clean_es_result(review_results_raw[0])
        average_rating = review_doc.get('平均评分')
        review_count = review_doc.get('评价数量')
        reviews_context = review_doc.get('所有评价')

        if not reviews_context:
            print(f"2. {series_name} 口碑数据中缺少[所有评价]字段。")
            return jsonify({"error": "口碑数据不完整，缺少评价内容。"}), 404

        print(f"2. 已汇总 {series_name} 的口碑数据。评分: {average_rating}, 数量: {review_count}")

        summary_prompt = create_summary_prompt(series_name, reviews_context, filter_context)
        llm_response = llm_client.chat.completions.create(
            model=DEEPSEEK_MODEL_NAME,
            messages=[
                {"role": "system", "content": "你是一个专业的汽车编辑，你的任务是总结用户口碑。"},
                {"role": "user", "content": summary_prompt}
            ],
            temperature=0.2
        )
        ai_summary = llm_response.choices[0].message.content if llm_response.choices else "AI总结生成失败，请稍后再试。"
        print(f"3. AI总结已生成。")

        return jsonify({
            "average_rating": average_rating,
            "review_count": review_count,
            "summary_text": ai_summary
        })

    except Exception as e:
        print(f"--- [AI SUMMARY ERROR] ---")
        traceback.print_exc()
        return jsonify({"error": f"生成AI总结时发生内部错误: {e}"}), 500


def create_summary_prompt(series_name, reviews_context, filter_context):
    context_prompt = f"请特别关注用户正在筛选的条件：【{filter_context}】，并在总结时优先体现与这些条件相关的优缺点。" if filter_context else ""
    return f"""
你是一个专业的汽车编辑，你的任务是分析给定车系的真实用户口碑，并用客观、精炼的语言总结出优点和缺点。
**任务:**
根据以下关于【{series_name}】车系的真实用户口碑，总结出用户最常提及的 3 个主要优点和 3 个主要缺点。
{context_prompt}
**规则:**
1.  **客观公正**: 严格基于提供的口碑原文，不要杜撰。
2.  **高度凝练**: 每个优点和缺点请用一句话概括。
3.  **引用佐证**: 在每一条总结后面，必须直接引用 1-2 句最相关的用户原话作为证据。
4.  **专注高频**: 只总结被多人反复提及的核心观点。
5.  **格式要求**: 必须严格按照以下格式输出，不要有任何多余的解释：
**【{series_name} - AI口碑总结】**
**主要优点:**
1.  **[优点1]**: [总结的优点一句话]
    * *用户评价佐证:* "[引用的用户原话...]"
2.  **[优点2]**: [总结的优点一句话]
    * *用户评价佐证:* "[引用的用户原话...]"
3.  **[优点3]**: [总结的优点一句话]
    * *用户评价佐证:* "[引用的用户原话...]"
**主要缺点:**
1.  **[缺点1]**: [总结的缺点一句话]
    * *用户评价佐证:* "[引用的用户原话...]"
2.  **[缺点2]**: [总结的缺点一句话]
    * *用户评价佐证:* "[引用的用户原话...]"
3.  **[缺点3]**: [总结的缺点一句话]
    * *用户评价佐证:* "[引用的用户原话...]"
---
**【用户口碑原文如下】:**
{reviews_context}
"""


@app.route('/ai_compare', methods=['POST'])
def ai_compare():
    if not llm_client:
        return jsonify({"error": "AI服务未配置或不可用"}), 503
    try:
        models_data = request.json
        if not models_data or not isinstance(models_data, list) or len(models_data) < 2:
            return jsonify({"error": "必须提供至少两个车型进行对比"}), 400

        print(f"\n--- [AI COMPARE DEBUG] ---")
        print(f"1. 收到 {len(models_data)} 个车型的对比请求。")

        key_fields_map = {
            "车型名称": "车型名称",
            "价格": "基本信息_厂商指导价",
            "动力类型": "动力类型",
            "发动机排量(L)": "发动机_排量[L]",
            "发动机最大功率(kW)": "发动机_最大功率[kW]",
            "电机总功率(kW)": "电机_总功率[kW]",
            "CLTC纯电续航(km)": "电池/补能_CLTC纯电续航里程[km]",
            "长*宽*高(mm)": "车身_长*宽*高[mm]",
            "轴距(mm)": "车身_轴距[mm]",
            "座位数": "车身_座位数",
            "辅助驾驶级别": "辅助驾驶硬件_驾驶辅助级别",
            "前排座椅功能": "座椅配置_第一排座椅功能",
            "中控屏尺寸": "车机/互联_中控屏尺寸[英寸]",
            "驱动形式": "底盘转向_驱动形式"
        }

        user_prompt_text = "请帮我详细对比以下几款车：\n\n"
        car_count = 1
        for model in models_data:
            model_name = model.get("车型名称", f"未知车型 {car_count}")
            user_prompt_text += f"--- 车型 {car_count}: 【{model_name}】 ---\n"

            for display_name, internal_key in key_fields_map.items():
                value = model.get(internal_key, "—")

                if value and value != "—" and value != "N/A" and value is not None:
                    user_prompt_text += f"- {display_name}: {value}\n"

            user_prompt_text += "\n"
            car_count += 1

        user_prompt_text += "--- 对比要求 ---\n"
        user_prompt_text += "请从【价格与性价比】、【动力与操控】、【空间与舒适性】和【智能化配置】这几个核心角度，用中文详细分析它们各自的【主要优点】和【主要缺点】。\n"
        user_prompt_text += "最后，请总结一下它们分别【适合什么样的人群】，并给我一个最终的购买建议。"

        system_prompt = "你是一个专业、资深、客观的汽车对比评测专家。你的任务是严格根据用户提供的几款车型的核心参数，生成一份详细的对比报告。请使用清晰、专业的语言，直接回答用户的对比要求，不要说多余的客套话。"

        print(f"2. 正在向 AI 发送对比 Prompt...")

        messages_to_send = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt_text}
        ]

        llm_response = llm_client.chat.completions.create(
            model=DEEPSEEK_MODEL_NAME,
            messages=messages_to_send,
            temperature=0.2
        )

        ai_summary = llm_response.choices[0].message.content if llm_response.choices else "AI总结生成失败，请稍后再试。"
        print(f"3. AI对比总结已生成。")

        return jsonify({"summary": ai_summary})

    except Exception as e:
        print(f"--- [AI COMPARE ERROR] ---")
        traceback.print_exc()
        return jsonify({"error": f"生成AI对比时发生内部错误: {e}"}), 500


@app.route('/api/admin/users', methods=['GET'])
@admin_required()
def admin_get_users():
    try:
        requesting_user = get_current_user_from_jwt()
        users_query = User.query.order_by(User.role.desc(), User.id)

        grouped_users = {
            "core_admin": [],
            "admin": [],
            "user": []
        }

        # core_admin 可以看到所有人
        if requesting_user.role == 'core_admin':
            all_users = users_query.all()
            for u in all_users:
                user_data = {"id": u.id, "username": u.username, "nickname": u.nickname, "role": u.role,
                             "is_banned": u.is_banned, "ban_reason": u.ban_reason}
                if u.role == 'core_admin':
                    grouped_users["core_admin"].append(user_data)
                elif u.role == 'admin':
                    grouped_users["admin"].append(user_data)
                else:
                    grouped_users["user"].append(user_data)

        # admin 只能看到 user
        elif requesting_user.role == 'admin':
            # 查询 'admin' 和 'user' 两种角色, 但排除 'core_admin'
            users_and_admins = users_query.filter(User.role.in_(['admin', 'user'])).all()

            for u in users_and_admins:
                user_data = {"id": u.id, "username": u.username, "nickname": u.nickname, "role": u.role,
                             "is_banned": u.is_banned, "ban_reason": u.ban_reason}

                if u.role == 'admin':
                    grouped_users["admin"].append(user_data)
                elif u.role == 'user':
                    grouped_users["user"].append(user_data)

            # 隐藏 core_admin 列表
            del grouped_users["core_admin"]

        return jsonify(grouped_users), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"获取用户列表时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/users/update_role', methods=['POST'])
@admin_required()
def admin_update_user_role():
    try:
        requesting_user = get_current_user_from_jwt()
        data = request.json
        user_id = data.get('user_id')
        new_role = data.get('new_role')

        if not user_id or not new_role:
            return jsonify({"error": "必须提供 user_id 和 new_role"}), 400

        if new_role not in ['user', 'admin']:
            return jsonify({"error": "无效的角色目标"}), 400

        user_to_update = User.query.get(int(user_id))
        if not user_to_update:
            return jsonify({"error": "目标用户不存在"}), 404

        if user_to_update.role == 'core_admin':
            return jsonify({"error": "权限不足：无法修改核心管理员"}), 403

        if requesting_user.role == 'admin':
            if user_to_update.role != 'user':
                return jsonify({"error": "权限不足：管理员只能管理普通用户"}), 403
            if new_role != 'user':
                return jsonify({"error": "权限不足：管理员不能提升他人权限"}), 403

        user_to_update.role = new_role
        db.session.commit()
        print(f"   -> (管理员操作 {requesting_user.username}：用户 {user_to_update.username} 角色已更新为 {new_role})")
        return jsonify({"message": "用户角色更新成功"}), 200

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"更新角色时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/users/ban', methods=['POST'])
@admin_required()
def admin_ban_user():
    try:
        requesting_user = get_current_user_from_jwt()
        data = request.json
        user_id = data.get('user_id')
        reason = data.get('reason', '无特定原因')

        if not user_id:
            return jsonify({"error": "必须提供 user_id"}), 400

        user_to_ban = User.query.get(int(user_id))
        if not user_to_ban:
            return jsonify({"error": "目标用户不存在"}), 404

        if user_to_ban.role == 'core_admin':
            return jsonify({"error": "权限不足：无法封禁核心管理员"}), 403
        if requesting_user.role == 'admin' and user_to_ban.role == 'admin':
            return jsonify({"error": "权限不足：管理员无法封禁其他管理员"}), 403

        user_to_ban.is_banned = True
        user_to_ban.ban_reason = reason
        db.session.commit()
        print(f"   -> (管理员操作 {requesting_user.username}：用户 {user_to_ban.username} 已被封禁)")
        return jsonify({"message": "用户封禁成功"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"封禁用户时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/users/unban', methods=['POST'])
@admin_required()
def admin_unban_user():
    try:
        requesting_user = get_current_user_from_jwt()
        data = request.json
        user_id = data.get('user_id')

        if not user_id:
            return jsonify({"error": "必须提供 user_id"}), 400

        user_to_unban = User.query.get(int(user_id))
        if not user_to_unban:
            return jsonify({"error": "目标用户不存在"}), 404

        if user_to_unban.role == 'core_admin':
            return jsonify({"error": "权限不足：无法操作核心管理员"}), 403
        if requesting_user.role == 'admin' and user_to_unban.role == 'admin':
            return jsonify({"error": "权限不足：管理员无法操作其他管理员"}), 403

        user_to_unban.is_banned = False
        user_to_unban.ban_reason = None
        db.session.commit()
        print(f"   -> (管理员操作 {requesting_user.username}：用户 {user_to_unban.username} 已被解封)")
        return jsonify({"message": "用户解封成功"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"解封用户时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@core_admin_required()
def admin_delete_user(user_id):
    try:
        data = request.json
        password = data.get('high_risk_password')

        is_valid, message = _verify_high_risk_password(password)
        if not is_valid:
            return jsonify({"error": message}), 403

        user_to_delete = User.query.get(user_id)
        if not user_to_delete:
            return jsonify({"error": "目标用户不存在"}), 404

        if user_to_delete.role == 'core_admin':
            return jsonify({"error": "无法删除核心管理员"}), 403

        username = user_to_delete.username
        db.session.delete(user_to_delete)
        db.session.commit()
        print(f"   -> (管理员操作：用户 {username} (ID: {user_id}) 已被删除)")
        return jsonify({"message": "用户删除成功"}), 200

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"删除用户时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/ai_config', methods=['GET'])
@core_admin_required()
def admin_get_ai_config():
    try:
        if not os.path.exists(MAPPING_FILE_PATH):
            return jsonify({"error": "配置文件 feature_mapping.json 未找到"}), 404

        with open(MAPPING_FILE_PATH, 'r', encoding='utf-8') as f:
            config_data = json.load(f)

        return jsonify(config_data), 200

    except json.JSONDecodeError:
        return jsonify({"error": "配置文件格式错误，不是一个有效的JSON"}), 500
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"读取配置时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/ai_config', methods=['POST'])
@core_admin_required()
def admin_save_ai_config():
    try:
        request_data = request.json
        if not isinstance(request_data, dict):
            return jsonify({"error": "无效的配置格式"}), 400

        password = request_data.pop('high_risk_password', None)
        new_config_data = request_data

        is_valid, message = _verify_high_risk_password(password)
        if not is_valid:
            return jsonify({"error": message}), 403

        with open(MAPPING_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(new_config_data, f, indent=2, ensure_ascii=False)

        global FEATURE_MAPPING
        FEATURE_MAPPING.clear()
        FEATURE_MAPPING.update(new_config_data)

        print(f"   -> (管理员操作：AI 特性映射已更新并热加载)")
        return jsonify({"message": "AI 配置保存成功，并已在服务器生效"}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"保存配置时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/vehicles/search', methods=['GET'])
@admin_required()
def admin_search_vehicles():
    if not es_client:
        return jsonify({"error": "ES 服务未连接"}), 503

    try:
        q = request.args.get('q', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = 20

        query_body = {
            "from": (page - 1) * per_page,
            "size": per_page,
            "query": {
                "bool": {
                    "must": [],
                    "should": [],
                    "minimum_should_match": 0
                }
            },
            "sort": ["_doc"]
        }

        if not q:
            query_body['query']['bool']['must'].append({"match_all": {}})
        else:
            query_body['query']['bool']['minimum_should_match'] = 1
            query_body['query']['bool']['should'] = [
                {"match_phrase_prefix": {"车型名称": {"query": q, "boost": 10}}},
                {"match_phrase_prefix": {"车系名称": {"query": q, "boost": 5}}},
                {"wildcard": {"车型名称.keyword": {"value": f"*{q}*", "case_insensitive": True, "boost": 2}}},
                {"wildcard": {"车系名称.keyword": {"value": f"*{q}*", "case_insensitive": True, "boost": 2}}}
            ]
            query_body['sort'] = [{"_score": "desc"}]

        response = es_client.search(index=INDEX_NAME, body=query_body)

        hits = response['hits']['hits']
        total = response['hits']['total']['value']

        return jsonify({
            "hits": hits,
            "total": total,
            "page": page,
            "per_page": per_page
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"搜索 ES 时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/vehicles/delete', methods=['POST'])
@admin_required()
def admin_delete_vehicle():
    if not es_client:
        return jsonify({"error": "ES 服务未连接"}), 503

    try:
        data = request.json
        doc_id = data.get('doc_id')

        password = data.get('high_risk_password')
        is_valid, message = _verify_high_risk_password(password)
        if not is_valid:
            return jsonify({"error": message}), 403
        if not doc_id:
            return jsonify({"error": "必须提供 doc_id"}), 400

        response = es_client.delete(index=INDEX_NAME, id=doc_id, ignore=[404])

        if response.get('result') == 'deleted':
            print(f"   -> (管理员操作：ES 文档 {doc_id} 已被删除)")
            return jsonify({"message": "文档删除成功"}), 200
        elif response.get('result') == 'not_found':
            return jsonify({"error": "文档未找到，可能已被删除"}), 404
        else:
            return jsonify({"error": "删除失败", "details": response}), 500

    except NotFoundError:
        return jsonify({"error": "文档未找到"}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"删除 ES 文档时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/vehicles/get/<string:doc_id>', methods=['GET'])
@admin_required()
def admin_get_vehicle_doc(doc_id):
    if not es_client:
        return jsonify({"error": "ES 服务未连接"}), 503
    try:
        response = es_client.get(index=INDEX_NAME, id=doc_id)
        return jsonify(response['_source']), 200

    except NotFoundError:
        return jsonify({"error": "未找到该文档 (ID: " + doc_id + ")"}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"获取 ES 文档时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/vehicles/update/<string:doc_id>', methods=['POST'])
@admin_required()
def admin_update_vehicle_doc(doc_id):
    if not es_client:
        return jsonify({"error": "ES 服务未连接"}), 503
    try:
        form_data = request.json
        if not form_data or not isinstance(form_data, dict):
            return jsonify({"error": "无效的JSON数据"}), 400
        if 'high_risk_password' in form_data:
            del form_data['high_risk_password']

        try:
            existing_doc_response = es_client.get(index=INDEX_NAME, id=doc_id)
            doc_data = existing_doc_response['_source']
        except NotFoundError:
            return jsonify({"error": "未找到该文档 (ID: " + doc_id + ")，无法更新"}), 404

        doc_data.update(form_data)

        doc_data['price_numeric'] = parse_price_to_numeric(doc_data.get('基本信息_厂商指导价'))
        doc_data['动力类型'] = clean_power_type(doc_data.get('动力类型'))
        doc_data['车身类型'] = clean_body_type(doc_data.get('基本信息_车身结构'))
        doc_data['车身_座位数'] = clean_seat_count(doc_data.get('基本信息_车身结构'))
        doc_data['基本信息_级别'] = clean_segment(doc_data.get('基本信息_级别'))
        model_name = doc_data.get('车型名称', '')
        doc_data['is_koubei_row'] = bool(isinstance(model_name, str) and '口碑' in model_name)

        if '图片链接' not in doc_data or not doc_data['图片链接']:
            doc_data['图片链接'] = 'https://p1.itc.cn/images01/20240306/633735165b3e4192be167d55f013d5a1.jpeg'

        final_doc = {k: v for k, v in doc_data.items() if v is not None}

        es_client.index(
            index=INDEX_NAME,
            id=doc_id,
            body=final_doc,
            refresh=True
        )

        print(f"   -> (管理员操作：ES 文档 {doc_id} 已被【v2修复并】更新)")
        return jsonify({"message": "文档更新成功"}), 200

    except NotFoundError:
        return jsonify({"error": "未找到该文档，无法更新"}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"更新 ES 文档时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/system/set_high_risk_password', methods=['POST'])
@core_admin_required()
def admin_set_high_risk_password():
    try:
        data = request.json
        new_password = data.get('password')

        if not new_password or len(new_password) < 6:
            return jsonify({"error": "密码长度不能少于6位"}), 400

        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        config = SystemConfig.query.get('high_risk_password')
        if config:
            config.value = hashed_pw
        else:
            config = SystemConfig(key='high_risk_password', value=hashed_pw)
            db.session.add(config)

        db.session.commit()
        print(f"   -> (管理员操作：高危操作密码已被重置)")
        return jsonify({"message": "高危操作密码设置成功"}), 200

    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({"error": f"设置密码时发生内部错误: {str(e)}"}), 500


def _run_subprocess(command):
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True
        )

        return process.stdout + (f"\n[Debug] {process.stderr}" if process.stderr else ""), None

    except subprocess.CalledProcessError as e:
        error_msg = f"导入/爬虫脚本执行失败 (Exit Code {e.returncode})：\n"
        error_msg += e.stdout + "\n" + e.stderr
        return None, error_msg
    except FileNotFoundError as e:
        error_msg = f"命令执行失败：找不到文件。\n{e}"
        return None, error_msg
    except Exception as e:
        error_msg = f"子进程发生未知错误：\n{e}"
        return None, error_msg


@app.route('/api/admin/system/run_crawler', methods=['POST'])
@admin_required()
def admin_run_crawler():
    try:
        urls_to_crawl = request.json.get('urls', [])
        if not urls_to_crawl or not all(isinstance(url, str) for url in urls_to_crawl):
            return jsonify({"error": "必须提供一个 URL 列表"}), 400

        try:
            if os.path.exists(CRAWLER_STATUS_FILE):
                with open(CRAWLER_STATUS_FILE, 'r', encoding='utf-8') as f:
                    status_data = json.load(f)
                    if status_data.get('status') == 'running':
                        return jsonify({"error": "启动失败：一个爬虫任务已经在后台运行中。"}), 409

            if os.path.exists(CRAWLER_LOG_FILE):
                os.remove(CRAWLER_LOG_FILE)

            with open(CRAWLER_STATUS_FILE, 'w', encoding='utf-8') as f:
                json.dump({"status": "starting", "message": "任务正在初始化..."}, f)

        except Exception as e:
            print(f"初始化状态文件时出错: {e}")

        python_executable = sys.executable or "python"
        command_args = " ".join(urls_to_crawl)
        command_str = (
            f'"{python_executable}" "{CRAWLER_SCRIPT_PATH}" {command_args} '
            f'> "{CRAWLER_LOG_FILE}" 2>&1'
        )

        print(f"--- [Admin Task] 异步执行爬虫 (同步启动检查) ---")
        print(f"CMD (Shell Mode): {command_str}")

        process = subprocess.Popen(
            command_str,
            shell=True,
            encoding='utf-8',
            errors='replace'
        )

        timeout = 5
        start_time = time.time()
        while time.time() - start_time < timeout:
            time.sleep(0.5)

            if os.path.exists(CRAWLER_STATUS_FILE):
                try:
                    with open(CRAWLER_STATUS_FILE, 'r', encoding='utf-8') as f:
                        status_data = json.load(f)
                        if status_data.get('status') in ['running', 'error']:
                            print(f"   -> (启动检查) 状态已更新为: {status_data.get('status')}")

                            return jsonify({"message": f"服务器已接受任务，启动检查通过。"}), 200
                except Exception:
                    pass

        if process.poll() is None:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)], capture_output=True, text=True)
            else:
                subprocess.run(['kill', '-9', str(process.pid)], capture_output=True, text=True)

            with open(CRAWLER_STATUS_FILE, 'w', encoding='utf-8') as f:
                json.dump({"status": "error", "message": "启动超时 (5秒)，子进程已强制终止。"}, f)

            return jsonify({"error": "启动超时：子进程未在 5 秒内报告状态。", "details": "请查看 crawler.log 文件"}), 500
        else:
            with open(CRAWLER_STATUS_FILE, 'w', encoding='utf-8') as f:
                json.dump({"status": "error", "message": "子进程启动后立刻崩溃，退出代码非零。"}, f)
            return jsonify({"error": "启动失败：子进程立刻崩溃。", "details": "请检查 crawler.log 文件"}), 500

    except Exception as e:
        traceback.print_exc()
        with open(CRAWLER_STATUS_FILE, 'w', encoding='utf-8') as f:
            json.dump({"status": "error", "message": "启动进程失败，请检查终端日志。"}, f)
        return jsonify({"error": f"启动爬虫时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/system/crawler_logs', methods=['GET'])
@admin_required()
def admin_get_crawler_logs():
    try:
        if not os.path.exists(CRAWLER_LOG_FILE):
            return jsonify({"logs": "任务未启动或日志文件不存在。", "status": "idle"})

        # 读取日志文件内容
        with open(CRAWLER_LOG_FILE, 'r', encoding='utf-8') as f:
            logs = f.read()

        # 读取状态文件以确定任务是否仍在运行
        current_status = "running"
        if os.path.exists(CRAWLER_STATUS_FILE):
            try:
                with open(CRAWLER_STATUS_FILE, 'r', encoding='utf-8') as f:
                    status_data = json.load(f)
                    current_status = status_data.get('status', 'running')
            except Exception:
                pass

        return jsonify({"logs": logs, "status": current_status}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"logs": f"无法读取日志文件: {str(e)}", "status": "error"}), 500


@app.route('/api/admin/system/stop_crawler', methods=['POST'])
@admin_required()  #
def admin_stop_crawler():
    try:
        if not os.path.exists(CRAWLER_STATUS_FILE):
            return jsonify({"error": "没有找到状态文件，无法停止。"}), 404

        pid_to_kill = None
        try:
            with open(CRAWLER_STATUS_FILE, 'r', encoding='utf-8') as f:
                status_data = json.load(f)
                pid_to_kill = status_data.get('pid')
        except Exception as e:
            print(f"读取状态文件时出错: {e}。将强制重置。")

        try:
            if not pid_to_kill:
                print(f"--- [Admin Task] 状态文件中没有PID，仅清理状态。 ---")
            else:
                print(f"--- [Admin Task] 正在尝试停止 PID: {pid_to_kill} ---")

                if os.name == 'nt':
                    command = ['taskkill', '/F', '/T', '/PID', str(pid_to_kill)]
                else:
                    command = ['kill', '-9', str(pid_to_kill)]

                stdout, stderr = _run_subprocess(command)

                if stderr:
                    print(f"--- [Admin Task] 停止命令返回信息 (可能是进程已不存在): {stderr} ---")

        except Exception as e:
            print(f"停止进程 {pid_to_kill} 时出错 (可能是进程已不存在): {e}")

        finally:
            with open(CRAWLER_STATUS_FILE, 'w', encoding='utf-8') as f:
                json.dump(
                    {"status": "idle", "message": f"任务 (PID: {pid_to_kill or '未知'}) 已被管理员强制停止或清理。"}, f)

            print(f"--- [Admin Task] 状态文件已强制重置为 idle ---")

        return jsonify({"message": f"成功发送停止命令并清理状态 (PID: {pid_to_kill})。"})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"停止任务时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/system/crawler_status', methods=['GET'])
@admin_required()  #
def admin_get_crawler_status():
    try:
        if not os.path.exists(CRAWLER_STATUS_FILE):
            return jsonify({"status": "idle", "message": "爬虫处于空闲状态。"})

        with open(CRAWLER_STATUS_FILE, 'r', encoding='utf-8') as f:
            status_data = json.load(f)
            return jsonify(status_data)

    except json.JSONDecodeError:
        return jsonify({"status": "error", "message": "错误：状态文件 (crawler.status) 格式损坏。"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"读取状态时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/system/download_latest_csv', methods=['GET'])
@admin_required()
def admin_download_latest_csv():
    try:
        script_dir = os.path.dirname(__file__)
        file_path = os.path.join(script_dir, CRAWLER_OUTPUT_FILE)

        if not os.path.exists(file_path):
            return jsonify({"error": f"文件 '{CRAWLER_OUTPUT_FILE}' 未找到。请先执行爬虫。"}), 404

        dynamic_filename = CRAWLER_OUTPUT_FILE
        if os.path.exists(CRAWLER_STATUS_FILE):
            try:
                with open(CRAWLER_STATUS_FILE, 'r', encoding='utf-8') as f:
                    status_data = json.load(f)
                    message = status_data.get('message', '')
                    match = re.search(r"数据已保存为:\s*(.+)", message)
                    if match:
                        dynamic_filename = match.group(1).strip()
            except Exception:
                pass

        return send_from_directory(
            script_dir,
            CRAWLER_OUTPUT_FILE,
            as_attachment=True,
            mimetype='text/csv',
            download_name=dynamic_filename
        )
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"下载文件时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/system/import_latest_csv', methods=['POST'])
@admin_required()  #
def admin_import_latest_csv():
    try:
        python_executable = sys.executable or "python"
        csv_path = os.path.join(os.path.dirname(__file__), CRAWLER_OUTPUT_FILE)

        if not os.path.exists(csv_path):
            return jsonify({"error": f"文件 '{CRAWLER_OUTPUT_FILE}' 未找到。请先执行爬虫。"}), 404

        print(f"--- [Admin Task] 同步导入最新爬虫数据 ---")
        command = [python_executable, IMPORTER_SCRIPT_PATH, csv_path]
        print(f"CMD: {' '.join(command)}")

        stdout, stderr = _run_subprocess(command)

        if stderr:
            return jsonify({"error": stderr}), 500

        return jsonify({"message": f"导入服务器文件 '{CRAWLER_OUTPUT_FILE}' 成功：\n\n{stdout}"}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"导入时发生内部错误: {str(e)}"}), 500


@app.route('/api/admin/system/upload_and_import', methods=['POST'])
@admin_required()  #
def admin_upload_and_import():
    try:
        # 检查是否有文件
        if 'files[]' not in request.files:
            return jsonify({"error": "未找到 'files[]' 文件部分"}), 400

        files = request.files.getlist('files[]')

        if not files or all(f.filename == '' for f in files):
            return jsonify({"error": "没有选择任何文件"}), 400

        temp_file_paths = []
        imported_filenames = []

        for file in files:
            if file and file.filename.endswith('.csv'):
                filename = secure_filename(file.filename)
                temp_path = os.path.join(UPLOAD_FOLDER, filename)
                file.save(temp_path)  #
                temp_file_paths.append(temp_path)
                imported_filenames.append(filename)

        if not temp_file_paths:
            return jsonify({"error": "没有上传有效的 .csv 文件"}), 400

        python_executable = sys.executable or "python"
        command = [python_executable, IMPORTER_SCRIPT_PATH] + temp_file_paths

        print(f"--- [Admin Task] 同步导入上传的 {len(temp_file_paths)} 个文件 ---")
        print(f"CMD: {' '.join(command)}")

        stdout, stderr = _run_subprocess(command)

        print(f"--- [Admin Task] 清理 {len(temp_file_paths)} 个临时文件 ---")
        for path in temp_file_paths:
            try:
                os.remove(path)
            except Exception as e:
                print(f"警告：删除临时文件 {path} 失败: {e}")

        if stderr:
            return jsonify({"error": f"导入文件时出错：\n\n{stderr}"}), 500

        return jsonify({
            "message": f"成功处理 {len(imported_filenames)} 个上传文件：\n{', '.join(imported_filenames)}\n\n【导入日志】:\n{stdout}"}), 200

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"上传文件时发生内部错误: {str(e)}"}), 500


@app.route('/debug/env')
def debug_env():
    """一个临时的调试接口，用来显示 Flask 正在使用的 Python.exe 路径"""
    print(f"Flask is using this Python: {sys.executable}")
    return f"Flask (app_ds2.py) 正在使用的 Python.exe 路径是: <br><br><strong>{sys.executable}</strong><br><br>请复制这条完整路径。"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
