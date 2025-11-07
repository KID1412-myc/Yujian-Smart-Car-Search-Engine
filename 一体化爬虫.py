import asyncio
import pandas as pd
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import re
import random
import numpy as np
import json

BRAND_URLS = [
    "https://car.yiche.com/chaojingqiche/"

]
MAX_PAGES_PER_MODEL = 1


async def scrape_single_car_config(page, url):
    print(f"  [配置] 正在爬取参数配置页: {url}")
    try:
        await page.goto(url, timeout=60000, wait_until="networkidle")
        await page.wait_for_selector(".parameter-container", timeout=20000)
        page_html = await page.content()
    except Exception as e:
        print(f"    -> [配置] 页面加载失败或未找到配置表: {url}, 错误: {e}")
        return None

    soup = BeautifulSoup(page_html, 'html.parser')
    main_model_name = "未知车系"
    title_tag = soup.select_one('.cx-brand-info h1 em, .p-block-title, .model-name')
    if title_tag:
        main_model_name = title_tag.text.strip().replace('参数配置', '').strip()
        print(f"    -> [配置] 成功识别车系为: {main_model_name}")
    else:
        print(f"    -> [配置] 未能自动识别车系名称")

    config_container = soup.find('div', class_='parameter-container')
    table = config_container.find('table', class_='main-param-table')
    if not table: return None

    header_row = table.find('tr', class_='t-header')
    headers = [th.text.strip() for th in header_row.find_all('span', class_='car-style-info')]
    all_car_data = [{'车型名称': name} for name in headers]
    current_category = "未知分类"
    rows = table.find('tbody').find_all('tr')
    for row in rows:
        if 't-header' in row.get('class', []): continue
        category_tag = row.find('h3')
        if category_tag:
            current_category = category_tag.text.strip()
            continue
        item_name_tag = row.find('td', attrs={'rowspan': '1'})
        if item_name_tag and item_name_tag.text.strip():
            item_name = item_name_tag.text.strip()
            full_key = f"{current_category}_{item_name}"
            values_tags = item_name_tag.find_next_siblings('td')
            values = []
            for val_tag in values_tags:
                cell_text = val_tag.get_text(strip=True)
                if '●' in cell_text:
                    values.append(cell_text.replace('●', '标配 ').strip())
                elif '○' in cell_text:
                    values.append(cell_text.replace('○', '选配 ').strip())
                elif cell_text == '-':
                    values.append('无')
                else:
                    values.append(cell_text if cell_text else '无')
            for i, car in enumerate(all_car_data):
                car[full_key] = values[i] if i < len(values) else '无'
    for car_record in all_car_data:
        car_record['车系名称'] = main_model_name
    return pd.DataFrame(all_car_data)


async def scrape_koubei_page(page, url):
    print(f"  [口碑] 正在爬取页面: {url}")
    try:
        await page.goto(url, timeout=60000, wait_until="domcontentloaded")
        if not await page.is_visible('.cm-content-moudle'):
            print("    -> [口碑] 页面中未发现点评内容，判定为最后一页。")
            return []
        page_html = await page.content()
    except Exception as e:
        print(f"    -> [口碑] 页面加载失败: {url}, 错误: {e}")
        return None
    soup = BeautifulSoup(page_html, 'html.parser')
    review_modules = soup.find_all('div', class_='cm-content-moudle')
    page_reviews = []
    for module in review_modules:
        try:
            page_reviews.append({
                "购买车型": module.find('p', class_='cm-car-name').text.strip() if module.find('p',
                                                                                               'cm-car-name') else "未知车型",
                "综合评分": module.find('span', class_='score').text.strip() if module.find('span', 'score') else None,
                "点评标题": module.find('div', class_='c-info-title').text.strip() if module.find('div',
                                                                                                  'c-info-title') else "无标题",
                "点评内容": module.find('div', class_='cm-content').find('p').text.strip() if module.find('div',
                                                                                                          'cm-content') and module.find(
                    'div', 'cm-content').find('p') else "",
            })
        except Exception as e:
            print(f"    -> [口碑] 解析单个点评时出错: {e}")
            continue
    return page_reviews


async def discover_car_series(page, brand_url):
    print(f"\n--- 正在访问品牌页: {brand_url} ---")
    series_info_list = []
    try:
        await page.goto(brand_url, timeout=60000, wait_until="domcontentloaded")
        html_content = await page.content()
        soup = BeautifulSoup(html_content, 'html.parser')

        brand_name_tag = soup.select_one('.brand-name')
        brand_name = brand_name_tag.text.strip() if brand_name_tag else "未知品牌"
        print(f"    -> [发现] 成功识别品牌为: {brand_name}")

        car_list_data = None
        try:
            car_list_data = await page.evaluate("() => window.carList")
        except Exception:
            print("    -> [发现] window.carList 未直接获取, 尝试从HTML源码中解析...")

        if not car_list_data:
            match = re.search(r'carList\s*=\s*(\{.*?\});', html_content, re.DOTALL)
            if match:
                try:
                    json_str = match.group(1).strip()
                    car_list_data = json.loads(json_str)
                    print("    -> [发现] 成功从HTML源码中解析 carList JSON。")
                except json.JSONDecodeError as e:
                    print(f"    -> [发现] 解析 window.carList JSON 失败: {e}")
                    car_list_data = None
            else:
                print("    -> [发现] 未能在HTML源码中找到 carList 数据。")

        if car_list_data and "onAndWaitList" in car_list_data:
            for manufacturer in car_list_data["onAndWaitList"]:
                if "serialList" in manufacturer:
                    for car_model in manufacturer["serialList"]:
                        if car_model.get("allSpell"):
                            all_spell = car_model['allSpell']
                            image_url = car_model.get("imageUrl", "").replace('{0}', '6')
                            if image_url and not image_url.startswith('http'):
                                image_url = 'https:' + image_url

                            series_info_list.append({
                                "brand": brand_name,
                                "config_url": f"https://car.yiche.com/{all_spell}/peizhi/",
                                "koubei_url": f"https://dianping.yiche.com/{all_spell}/koubei/",
                                "图片链接": image_url
                            })
            print(f"品牌 '{brand_name}' 下发现了 {len(series_info_list)} 个车系。")
            return series_info_list
    except Exception as e:
        print(f"处理品牌页 {brand_url} 时出错: {e}")
        return []


async def main():
    all_final_data = []
    print("--- 启动一体化爬取任务 ---")
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="msedge", headless=True)
        page = await browser.new_page()
        for brand_url in BRAND_URLS:
            car_series_list = await discover_car_series(page, brand_url)
            for series in car_series_list:
                config_df = await scrape_single_car_config(page, series["config_url"])
                await asyncio.sleep(random.uniform(1, 2))
                if config_df is None or config_df.empty:
                    print(f"    -> 跳过车系，未能获取参数配置。 URL: {series['config_url']}")
                    continue

                series_image_url = series.get("图片链接", "")
                brand_name = series.get("brand", "未知品牌")
                config_df['图片链接'] = series_image_url
                config_df['品牌'] = brand_name  # 新增品牌列

                print(f"    -> [配置] 成功爬取 {len(config_df)} 款具体车型的配置。")
                all_final_data.append(config_df)

                all_reviews_list = []
                base_koubei_url = series["koubei_url"]
                for page_num in range(1, MAX_PAGES_PER_MODEL + 1):
                    current_url = base_koubei_url if page_num == 1 else f"{base_koubei_url.replace('/koubei/', '')}/koubei-{page_num}.html"
                    reviews = await scrape_koubei_page(page, current_url)
                    if reviews:
                        all_reviews_list.extend(reviews)
                        print(f"    -> [口碑] 第 {page_num} 页成功爬取 {len(reviews)} 条点评。")
                    else:
                        break
                    await asyncio.sleep(random.uniform(1, 3))

                if all_reviews_list:
                    reviews_df = pd.DataFrame(all_reviews_list)
                    reviews_df['综合评分'] = pd.to_numeric(reviews_df['综合评分'], errors='coerce')
                    reviews_df.dropna(subset=['综合评分'], inplace=True)

                    if not reviews_df.empty:
                        reviews_df['评价全文_带车型'] = "[用户填写车型: " + reviews_df['购买车型'].astype(str) + "] " + \
                                                        "【" + reviews_df['点评标题'].astype(str) + "】 " + \
                                                        reviews_df['点评内容'].astype(str)

                        series_name = config_df['车系名称'].iloc[0]
                        series_avg_score = reviews_df['综合评分'].mean()
                        series_review_count = len(reviews_df)
                        series_all_reviews = '\n\n'.join(reviews_df['评价全文_带车型'])

                        general_reviews_row = {
                            '品牌': brand_name,
                            '车系名称': series_name,
                            '车型名称': f"[{series_name} 车系通用口碑]",
                            '平均评分': round(series_avg_score, 2),
                            '评价数量': series_review_count,
                            '所有评价': series_all_reviews,
                            '图片链接': series_image_url
                        }
                        all_final_data.append(pd.DataFrame([general_reviews_row]))
                        print(
                            f"    -> [整合] 已为车系 '{series_name}' 创建了包含 {series_review_count} 条口碑的独立汇总行。")
        await browser.close()

    if not all_final_data:
        print("\n--- 任务完成，但没有爬取到任何数据。 ---")
        return

    print("\n--- 所有数据爬取完毕，开始进行最终整合与保存 ---")
    master_df = pd.concat(all_final_data, ignore_index=True)
    if '评价数量' not in master_df.columns:
        master_df['评价数量'] = 0
    else:
        master_df['评价数量'] = master_df['评价数量'].fillna(0).astype(int)

    if '所有评价' not in master_df.columns:
        master_df['所有评价'] = ''
    else:
        master_df['所有评价'] = master_df['所有评价'].fillna('')

    if '平均评分' not in master_df.columns:
        master_df['平均评分'] = np.nan
    if '图片链接' not in master_df.columns:
        master_df['图片链接'] = ''
    master_df['图片链接'] = master_df['图片链接'].fillna('')

    if '品牌' not in master_df.columns:
        master_df['品牌'] = '未知品牌'
    master_df['品牌'] = master_df['品牌'].fillna('未知品牌')

    core_cols = ['品牌', '车系名称', '车型名称', '平均评分', '评价数量', '所有评价', '图片链接']
    config_cols = [col for col in master_df.columns if col not in core_cols]
    new_order = core_cols + sorted(config_cols)
    master_df = master_df.reindex(columns=new_order)

    output_filename = f"易车_超境参数与口碑汇总.csv"
    master_df.to_csv(output_filename, index=False, encoding='utf-8-sig')

    print(f"\n🎉🎉🎉 一体化爬取与整合任务全部完成！🎉🎉🎉")
    print(f"共生成 {len(master_df)} 条数据记录（包含车型配置与口碑汇总行）。")
    print(f"数据已全部汇总并保存至: {output_filename}")


if __name__ == "__main__":
    asyncio.run(main())
