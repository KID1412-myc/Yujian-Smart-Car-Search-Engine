import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import re
import numpy as np
import traceback
import os
import glob

ES_HOST = "localhost"
ES_PORT = 9200
INDEX_NAME = "yiche_cars"
DATA_DIR = "D://python_project//搜索引擎扩展//车数据//"

index_settings = {
    "analysis": {
        "char_filter": {
            "space_remover": {
                "type": "mapping",
                "mappings": ["\\u0020 => "]
            }
        },
        "analyzer": {
            "my_custom_search_analyzer": {
                "type": "custom",
                "char_filter": ["space_remover"],
                "tokenizer": "ik_smart",
                "filter": ["lowercase"]
            }
        }
    }
}

index_mappings = {
    "date_detection": False,
    "numeric_detection": False,
    "dynamic_templates": [
        {
            "strings_as_keywords": {
                "match_mapping_type": "string",
                "mapping": {"type": "keyword"}
            }
        }
    ],
    "properties": {
        "品牌": {
            "type": "text",
            "analyzer": "my_custom_search_analyzer",
            "fields": {"keyword": {"type": "keyword"}}
        },
        "基本信息_厂商": {
            "type": "text",
            "analyzer": "my_custom_search_analyzer",
            "fields": {"keyword": {"type": "keyword"}}
        },
        "车系名称": {
            "type": "text",
            "analyzer": "my_custom_search_analyzer",
            "fields": {"keyword": {"type": "keyword"}}
        },
        "车型名称": {
            "type": "text",
            "analyzer": "my_custom_search_analyzer",
            "fields": {"keyword": {"type": "keyword"}}
        },
        "所有评价": {"type": "text", "analyzer": "ik_max_word"},
        "is_koubei_row": {"type": "boolean"},
        "price_numeric": {"type": "float"},
        "图片链接": {"type": "keyword", "index": False},
        "基本信息_级别": {"type": "keyword"},
        "车身_座位数": {"type": "keyword"},
        "动力类型": {"type": "keyword"},
        "车身类型": {"type": "keyword"},
        "基本信息_最高车速[km/h]": {"type": "keyword"},
        "基本信息_WLTC综合油耗[L/100km]": {"type": "keyword"},
        "发动机_最大净功率[kW]": {"type": "keyword"},
        "车身_实测前备厢容积[L]": {"type": "keyword"},
        "电池/补能_快充时间[h]": {"type": "keyword"},
        "发动机_压缩比": {"type": "keyword"},
        "车身_官方前备厢容积[L]": {"type": "keyword"},
        "车身_实测后备厢容积[L]": {"type": "keyword"},
        "车身_轴距[mm]": {"type": "keyword"},
        "车轮制动_轮胎数": {"type": "keyword"},
        "基本信息_慢充时间[小时]": {"type": "keyword"},
        "电池/补能_慢充时间[h]": {"type": "keyword"},
        "变速箱_挡位数": {"type": "keyword"},
        "平均评分": {"type": "float"},
        "评价数量": {"type": "integer"},
        "评价条数": {"type": "integer"}
    }
}


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


def generate_actions(dataframe):
    for record in dataframe.to_dict('records'):
        doc = {k: v for k, v in record.items() if v is not None}

        doc['price_numeric'] = parse_price_to_numeric(doc.get('基本信息_厂商指导价'))
        doc['动力类型'] = clean_power_type(doc.get('动力类型'))
        doc['车身类型'] = clean_body_type(doc.get('基本信息_车身结构'))
        doc['车身_座位数'] = clean_seat_count(doc.get('基本信息_车身结构'))
        doc['基本信息_级别'] = clean_segment(doc.get('基本信息_级别'))

        model_name = doc.get('车型名称', '')
        doc['is_koubei_row'] = bool(isinstance(model_name, str) and '口碑' in model_name)

        if '图片链接' not in doc or not doc['图片链接']:
            doc['图片链接'] = 'https://p1.itc.cn/images01/20240306/633735165b3e4192be167d55f013d5a1.jpeg'

        final_doc = {k: v for k, v in doc.items() if v is not None}

        yield {
            "_index": INDEX_NAME,
            "_source": final_doc
        }


def main():
    try:
        es_client = Elasticsearch(
            [{'host': ES_HOST, 'port': ES_PORT, 'scheme': 'http'}],
            timeout=60
        )
        if not es_client.ping():
            raise ConnectionError("无法连接到Elasticsearch！请检查ES服务是否已启动。")
        print("Elasticsearch 连接成功！")

        if es_client.indices.exists(index=INDEX_NAME):
            print(f"索引 '{INDEX_NAME}' 已存在，将直接导入数据。")

        else:
            print(f"索引 '{INDEX_NAME}' 不存在，正在使用新结构创建...")
            es_client.indices.create(
                index=INDEX_NAME,
                settings=index_settings,
                mappings=index_mappings
            )
            print("新索引创建成功！(使用了自定义分析器和更新的映射)")

        csv_files = glob.glob(os.path.join(DATA_DIR, '易车_*.csv'))
        csv_files.sort()

        if not csv_files:
            print(f"错误：在目录 '{DATA_DIR}' 未找到任何 '易车_*.csv' 文件。")
            return

        print(f"将在 '{DATA_DIR}' 目录下按顺序导入以下文件:")
        for f in csv_files:
            print(f"  - {os.path.basename(f)}")
        print("-" * 30)

        total_success = 0
        total_failed_count = 0

        for file_path in csv_files:
            file_name = os.path.basename(file_path)
            print(f"\n--- 开始处理文件: {file_name} ---")
            try:
                print(f"从 '{file_path}' 读取数据...")
                df = pd.read_csv(file_path, na_values=['无'])

                if '基本信息_能源类型' in df.columns:
                    df.rename(columns={'基本信息_能源类型': '动力类型'}, inplace=True)

                df = df.replace({np.nan: None})
                numeric_cols = ['平均评分', '评价数量', '评价条数']
                for col in numeric_cols:
                    if col in df.columns:
                        df[col] = pd.to_numeric(df[col], errors='coerce').replace({np.nan: None})
                print("数据读取和初步清洗成功！")

                print("正在向Elasticsearch中导入数据...")
                success, failed = bulk(
                    es_client,
                    generate_actions(df),
                    chunk_size=500,
                    request_timeout=120,
                    raise_on_error=False
                )
                print(f"文件 '{file_name}' 导入完成！成功: {success}, 失败: {len(failed)}")
                total_success += success
                total_failed_count += len(failed)

                if failed:
                    print(f"文件 '{file_name}' 中 {len(failed)} 个文档导入失败，详情如下:")

                    for i, item in enumerate(failed[:10]):
                        print(f"  - 失败 {i + 1}: {item}")
                    if len(failed) > 10:
                        print(f"  ... (还有 {len(failed) - 10} 个错误未显示)")

            except FileNotFoundError:
                print(f"\n错误：导入文件 '{file_name}' 时找不到该文件。跳过...")
            except pd.errors.EmptyDataError:
                print(f"\n警告：文件 '{file_name}' 为空或格式错误。跳过...")
            except Exception as e:
                print(f"\n处理文件 '{file_name}' 时发生严重错误: {e}")
                traceback.print_exc()
                print("继续处理下一个文件...")

        print("-" * 30)
        print(f"\n所有文件处理完毕。总成功: {total_success}, 总失败: {total_failed_count}")

    except ConnectionError as e:
        print(f"\n错误: {e}")
    except Exception as e:
        print(f"\n处理过程中发生错误: {e}")
        traceback.print_exc()


if __name__ == '__main__':
    main()
