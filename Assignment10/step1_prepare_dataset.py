import json
import os
import time
import random
from dotenv import load_dotenv
import google.generativeai as genai
from datasets import load_dataset

# =============================================
# 1. 設定 Gemini
# =============================================
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
gemini = genai.GenerativeModel("gemini-2.5-flash")

# =============================================
# 2. 下載資料集並抽樣
# =============================================
print("正在下載 deepset/prompt-injections...")
dataset = load_dataset("deepset/prompt-injections", split="train")
print(f"總筆數: {len(dataset)}")

benign = [x for x in dataset if x["label"] == 0]
injection = [x for x in dataset if x["label"] == 1]
print(f"正常: {len(benign)} 筆, 攻擊: {len(injection)} 筆")

random.seed(42)
sampled_benign = random.sample(benign, min(250, len(benign)))
sampled_injection = random.sample(injection, min(250, len(injection)))
sampled = sampled_benign + sampled_injection
random.shuffle(sampled)
print(f"抽樣後: {len(sampled)} 筆")

# =============================================
# 3. 批次轉換（每次 10 筆）
# =============================================
BATCH_SIZE = 10

prompt_template = """你是一位資安專家，專精於 LLM 安全與 Prompt Injection 偵測。

以下有 {count} 段使用者輸入，每段都標註了是「攻擊」還是「正常」。
請為每一段生成分析，用以下固定格式：

判定：[Prompt Injection 攻擊 / 正常請求]
類型：[若為攻擊：指令覆蓋/角色劫持/系統提示詞洩漏/夾帶攻擊/偽造系統訊息/越獄攻擊/編碼繞過 等；若為正常：無]
分析：[2-3句話，具體說明判定理由]
風險等級：[高/中/低/無]
建議處置：[一句話建議]

輸入資料：
{items}

請回傳一個 JSON array，每個元素包含：
- "instruction": "判斷以下使用者輸入是否為 prompt injection 攻擊，並說明理由。"
- "input": 原始使用者輸入文字
- "output": 你的分析結果（上面的格式）

只回傳 JSON array，不要任何前綴、說明或 markdown 標記。"""

all_data = []
total_batches = (len(sampled) + BATCH_SIZE - 1) // BATCH_SIZE

for i in range(0, len(sampled), BATCH_SIZE):
    batch = sampled[i:i + BATCH_SIZE]
    batch_num = i // BATCH_SIZE + 1
    print(f"\n=== 批次 {batch_num}/{total_batches} ===")
    
    # 組裝這批的輸入
    items_text = ""
    for idx, item in enumerate(batch):
        label_str = "攻擊" if item["label"] == 1 else "正常"
        items_text += f"\n[第{idx+1}筆] 標註：{label_str}\n輸入：{item['text']}\n"
    
    prompt = prompt_template.format(count=len(batch), items=items_text)
    
    try:
        response = gemini.generate_content(prompt)
        text = response.text.strip()
        
        # 清理 markdown 標記
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.strip()
        
        batch_data = json.loads(text)
        all_data.extend(batch_data)
        print(f"  成功：{len(batch_data)} 筆（累計 {len(all_data)} 筆）")
        
    except json.JSONDecodeError as e:
        print(f"  [JSON 解析失敗] {e}")
        print(f"  回應前 300 字: {response.text[:300]}")
        # fallback: 用固定模板
        for item in batch:
            if item["label"] == 1:
                output = "判定：Prompt Injection 攻擊\n類型：指令覆蓋\n分析：該輸入包含試圖操控模型行為的惡意指令，意圖繞過安全限制。\n風險等級：高\n建議處置：拒絕執行並記錄該請求。"
            else:
                output = "判定：正常請求\n類型：無\n分析：該輸入為一般性請求，內容合理且未包含操控意圖。\n風險等級：無\n建議處置：正常回應。"
            all_data.append({
                "instruction": "判斷以下使用者輸入是否為 prompt injection 攻擊，並說明理由。",
                "input": item["text"],
                "output": output
            })
        print(f"  使用 fallback 模板（累計 {len(all_data)} 筆）")
        
    except Exception as e:
        print(f"  [錯誤] {e}")
    
    time.sleep(10)  # 避免 rate limit

# =============================================
# 4. 儲存
# =============================================
print(f"\n{'=' * 60}")
print(f"總共: {len(all_data)} 筆")

attack_count = sum(1 for d in all_data if "攻擊" in d.get("output", ""))
benign_count = len(all_data) - attack_count
print(f"攻擊: {attack_count} 筆, 正常: {benign_count} 筆")

output_path = "prompt_injection_sft.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(all_data, f, ensure_ascii=False, indent=2)

print(f"已儲存到 {output_path}")

# 預覽
print("\n預覽前 2 筆：")
for idx, item in enumerate(all_data[:2]):
    print(f"\n--- 第 {idx+1} 筆 ---")
    print(f"input: {item['input'][:100]}...")
    print(f"output:\n{item['output']}")
