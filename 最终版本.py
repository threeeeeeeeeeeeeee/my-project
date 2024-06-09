import tkinter as tk
from tkinter import simpledialog, messagebox
import re
import collections
import tkinter.simpledialog

def create_cipher(key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    cipher = {}
    for i in range(len(alphabet)):
        cipher[alphabet[i]] = key[i]
    return cipher

def encrypt():
    key = key_entry.get().lower()
    plaintext = plaintext_entry.get().lower()

    if len(key) != 26 or not key.isalpha():
        messagebox.showerror("错误", "密钥必须是包含26个字母的置换。")
        return

    cipher = create_cipher(key)
    encrypted_text = ""
    for char in plaintext:
        if char in cipher:
            encrypted_text += cipher[char]
        else:
            encrypted_text += char

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, encrypted_text)

def decrypt():
    key = key_entry.get().lower()
    ciphertext = ciphertext_entry.get().lower()

    if len(key) != 26 or not key.isalpha():
        messagebox.showerror("错误", "密钥必须是包含26个字母的置换。")
        return

    cipher = create_cipher(key)
    reverse_cipher = {v: k for k, v in cipher.items()}
    decrypted_text = ""
    for char in ciphertext:
        if char in reverse_cipher:
            decrypted_text += reverse_cipher[char]
        else:
            decrypted_text += char

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, decrypted_text)
# 第一步函数：第二个按钮的功能
def show_suggestion_buttons():
    global text
    text = input_text.get("1.0", tk.END).lower()  # 将输入的文本保存在全局变量中
    suggestion_label.pack()  # 显示建议按钮的标签
    button1.pack()  # 显示建议按钮1
    button2.pack()  # 显示建议按钮2
    button3.pack()  # 显示建议按钮3

###三个按钮的功能
def fre_suggest_decryption(ciphertext):
    frequency_analysis_suggestion = "基于频率分析的破译建议："
    cipher_counter = collections.Counter(char for char in ciphertext if char != ' ') # 统计密文中字母的频率，忽略空格
    # 按照频率从高到低排序
    sorted_cipher_freq = cipher_counter.most_common(5)  # 取出前五个频率最高的字母及其频率
    target_letters = ['e', 't', 'a', 'o', 'i']  # 目标字母
    suggested_mapping = {}  # 初始化推测的替换关系
    for i in range(min(5, len(sorted_cipher_freq))):  # 遍历前五个频率最高的字母
        cipher = sorted_cipher_freq[i][0]  # 当前字母
        plain = target_letters[i]  # 对应的目标字母
        suggested_mapping[cipher] = plain  # 记录替换关系
    frequency_analysis_suggestion += "根据频率分析，建议将\n"
    for cipher, plain in suggested_mapping.items():
        frequency_analysis_suggestion += f" '{cipher}' 替换为 '{plain}'\n"
    frequency_analysis_suggestion = frequency_analysis_suggestion.rstrip(',') + "。"

    suggestions = frequency_analysis_suggestion

    return suggestions

# 统计英文字母出现频率
def get_letter_frequency(text):
    frequency = {}
    total_letters = 0
    for char in text:
        if char.isalpha():
            char = char.lower()
            frequency[char] = frequency.get(char, 0) + 1
            total_letters += 1
    # 按照字母频率从高到低排序
    sorted_frequency = {char: freq / total_letters for char, freq in sorted(frequency.items(), key=lambda item: item[1], reverse=True)}
    
    return sorted_frequency

#分析单词the
def count_three_letter_words(text):
    print("三个字母组成的单词的次数如下")
    words = re.findall(r'\b[a-zA-Z]{3}\b', text)  # 使用正则表达式找出所有由三个字母组成的单词
    word_count = {}
    for word in words:
        if word.lower() in word_count:
            word_count[word.lower()] += 1
        else:
            word_count[word.lower()] = 1
    sorted_word_count = dict(sorted(word_count.items(), key=lambda x: x[1], reverse=True))
    top_three_words = list(sorted_word_count.items())[:3]
    output_str = ""
    for word, count in top_three_words:
        output_str += f"{word} 出现了 {count} 次\n"
    max_freq_word = list(sorted_word_count.keys())[0]
    output_str += f"{max_freq_word}可能为the\n"
    return output_str

# 加载常见英文单词库
def load_english_words():
    with open('D:\\2024年春密码学大作业\\english_words.txt.txt', 'r') as file:
        words = file.read().splitlines()
    return set(words) 

# 解密函数
def suggest_decryption(ciphertext, key_mapping, known_words):
    # 可以根据已知密钥字替换密文中的字符
    plaintext = ''.join(key_mapping.get(c, c) for c in ciphertext)
    # 根据上下文和统计规律给出破译建议
    # 这里可以根据具体算法进行建议的生成
    suggestions = "根据上下文和统计规律给出的破译建议"
    return suggestions, plaintext

#字母连接特征
def analyze_text_and_display(text):
    result = ""
    for i in range(len(text)):
        if text[i] == 'Q' and i < len(text) - 1 and text[i + 1].isalpha() and text[i+1]!=' ' and text[i+1]!='U':
            result += f"{text[i+1]}可能是u\n"
        elif text[i] == 'X' and i > 0 and text[i - 1].isalpha() and text[i-1]!=' ' and text[i-1]!='I' and text[i-1]!='E':
            result += f"{text[i-1]}可能是i或者e，几乎不可能是o或a\n"
        elif text[i] == 'E' and i < len(text) - 2 and text[i + 2] == 'E' and text[i+1]!=' ' and text[i+1]!='R':
            result += f"{text[i+1]}可能为r\n"
    return result


def function1(text):
    # 调用 get_letter_frequency 函数获取字母频率
    frequency = get_letter_frequency(text)
    output_text = "字母频率：\n"
    for char, freq in frequency.items():
        output_text += f"字母 '{char}' 出现的频率为: {freq:.2%}\n"

    #基于字母统计规律的建议
    suggestions = fre_suggest_decryption(text)
    output_text += "\n基于字母统计规律的建议：\n" + suggestions

    # 创建一个弹出窗口来显示输出信息
    messagebox.showinfo("输出信息", output_text)

def function2(text):
    #基于三个字母的单词给出的规律
    result = count_three_letter_words(text)
    messagebox.showinfo("输出信息", result)

def function3_dialog(text):
    ciphertext = text
    known_words = load_english_words()
    key_mapping = {}  # 初始化密钥字典，可以根据需求进行初始化
    while True:
        suggestions, plaintext = suggest_decryption(ciphertext, key_mapping, known_words)
        
        analysis_result = analyze_text_and_display(plaintext)
        messagebox.showinfo("文本分析结果", analysis_result)

        messagebox.showinfo("当前破译结果", plaintext)
        user_input = simple_input_dialog("请输入你的调整（格式：密钥字=明文字，如a=t），或输入'完成'结束：")
        if user_input == '完成':
            break
        # 解析用户输入的密钥字，更新key_mapping
        match = re.match(r'(\w)=(\w)', user_input)
        if match:
            key, value = match.groups()
            key_mapping[key] = value  # 不转换为大写字母
        else:
            messagebox.showwarning("警告", "无效的输入，请重新输入。")

def show_suggestion_buttons():
    # 弹出对话框获取待解密文本
    ciphertext = tkinter.simpledialog.askstring("输入密文", "请输入待解密的密文：")

    # 如果用户点击了取消按钮或者未输入任何内容，则返回
    if ciphertext is None or ciphertext.strip() == "":
        return

    # 显示建议按钮
    button1.pack()
    button2.pack()
    button3.pack()

    # 将用户输入的密文显示在输入框中
    ciphertext_entry.delete(0, tk.END)
    ciphertext_entry.insert(tk.END, ciphertext)
    
    # 返回用户输入的密文
    return ciphertext

def simple_input_dialog(prompt):
    # 创建一个简单的输入对话框
    root = tk.Tk()
    root.withdraw()
    user_input = simpledialog.askstring("输入", prompt)
    return user_input




# 创建主界面
root = tk.Tk()
root.title("代换密码工具")

# 密钥输入
key_label = tk.Label(root, text="请输入密钥（26个字母的置换）：")
key_label.pack()
key_entry = tk.Entry(root)
key_entry.pack()

# 明文输入
plaintext_label = tk.Label(root, text="请输入要加密的明文：")
plaintext_label.pack()
plaintext_entry = tk.Entry(root)
plaintext_entry.pack()

# 密文输入
ciphertext_label = tk.Label(root, text="请输入要解密的密文：")
ciphertext_label.pack()
ciphertext_entry = tk.Entry(root)
ciphertext_entry.pack()

# 加密按钮
encrypt_button = tk.Button(root, text="加密", command=encrypt)
encrypt_button.pack()

# 解密按钮
decrypt_button = tk.Button(root, text="解密", command=decrypt)
decrypt_button.pack()

# 输出结果
output_label = tk.Label(root, text="输出结果：")
output_label.pack()
output_text = tk.Text(root, height=6, width=50)
output_text.pack()

#ciphertext_entry = tk.Entry(root)
#ciphertext_entry.pack()

# 创建按钮1
button1 = tk.Button(root, text="通过字母频率提供建议", command=lambda: function1(ciphertext_entry.get()))

# 创建按钮2
button2 = tk.Button(root, text="根据常用单词提供建议", command=lambda: function2(ciphertext_entry.get()))

# 创建按钮3
button3 = tk.Button(root, text="根据语言习惯提供建议", command=lambda: function3_dialog(ciphertext_entry.get()))


# 创建标签用于显示建议
suggestion_label = tk.Label(root, text="请选择以下建议：")
suggestion_label.pack()

# 创建按钮2，点击后获取待解密文本并显示建议按钮
button_2 = tk.Button(root, text="密钥未知", command=show_suggestion_buttons)
button_2.pack()

root.mainloop()
