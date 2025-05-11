import hashlib
import os
import json
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple
import openai
import logging

logger = logging.getLogger(__name__)


class CodeAnalysisChatSystem:
    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com/v1"):
        """
        初始化代码分析聊天系统

        参数：
            api_key: DeepSeek API密钥
            base_url: API基础地址（默认为DeepSeek官方端点）
        """
        self.api_key = api_key
        self.base_url = base_url
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)

        # 对话和代码上下文管理
        self.conversation_history: List[Dict] = []  # 存储完整对话历史
        self.code_context: Dict[str, Dict] = {}  # 代码文件路径 -> {content, analysis}
        self.analysis_cache: Dict[str, str] = {}  # 代码分析结果缓存

        # 工作区配置
        self.workspace = Path("workspace")
        self.workspace.mkdir(exist_ok=True)

        # 项目相关状态
        self.current_project: Optional[Path] = None  # 当前项目根目录
        self.active_file: Optional[str] = None  # 当前活动代码文件

        # 初始化缓存目录
        self.cache_dir = self.workspace / "cache"
        self.cache_dir.mkdir(exist_ok=True)

        # 上下文相关配置
        self.max_context_length = 4000  # 最大上下文token数
        self.context_strategy = "smart"  # 上下文处理策略

    def chat(self,
             message: str,
             use_code_context: bool = False,
             file_path: Optional[str] = None,
             zip_path: Optional[str] = None,  # 新增 ZIP 文件路径参数
             context: Optional[List[Dict]] = None) -> str:
        """
        与AI系统对话的核心方法

        参数:
            message: 用户消息
            use_code_context: 是否使用代码上下文
            file_path: 关联的代码文件路径（可选）
            zip_path: 关联的ZIP文件路径（可选）
            context: 自定义上下文消息列表（可选）
        """
        # 构建基础消息
        messages = [{"role": "system", "content": "你是一个专业的代码分析助手"}]

        # 添加自定义上下文（如果有）
        if context:
            messages.extend(context)

        # 处理ZIP文件上下文（如果提供）
        if use_code_context and zip_path:
            try:
                # 分析ZIP文件内容
                zip_analysis = self.analyze_zip(zip_path)
                messages.append({
                    "role": "system",
                    "content": f"项目分析摘要:\n{json.dumps(zip_analysis['_summary'], indent=2)}"
                })

                # 如果指定了具体文件，添加该文件内容
                if file_path and file_path in zip_analysis:
                    file_data = zip_analysis[file_path]
                    messages.append({
                        "role": "system",
                        "content": f"文件 {file_path} 内容:\n{file_data['content'][:2000]}\n分析:\n{file_data['analysis']}"
                    })
            except Exception as e:
                logger.error(f"ZIP分析失败: {str(e)}")
                messages.append({
                    "role": "system",
                    "content": f"警告: 无法分析ZIP文件 {zip_path}"
                })

        # 添加用户消息
        messages.append({"role": "user", "content": message})

        # 调用AI接口
        response = self.client.chat.completions.create(
            model="deepseek-coder",
            messages=messages,
            temperature=0.7,
            max_tokens=2000
        )

        return response.choices[0].message.content

    def analyze_zip(self, zip_path: str) -> Dict:
        """ZIP分析方法"""
        try:
            # 1. 创建临时解压目录
            temp_dir = Path(self.workspace) / "temp" / hashlib.md5(zip_path.encode()).hexdigest()
            temp_dir.mkdir(parents=True, exist_ok=True)

            # 2. 解压文件
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            # 3. 分析项目结构
            analysis = {
                "_project_structure": self._analyze_project_structure(temp_dir),
                "_summary": {}
            }

            # 4. 分析代码文件
            for file in temp_dir.rglob("*"):
                if file.is_file() and self._is_code_file(file.name):
                    rel_path = str(file.relative_to(temp_dir))
                    try:
                        content = self._safe_read_file(file)
                        if content:
                            analysis[rel_path] = {
                                "content": content,
                                "analysis": self._analyze_file(file, content)
                            }
                    except Exception as e:
                        logger.error(f"分析文件 {rel_path} 失败: {str(e)}")
                        analysis[rel_path] = {"error": str(e)}

            # 5. 生成摘要
            analysis["_summary"] = self._generate_zip_summary(analysis)
            return analysis

        except Exception as e:
            logger.error(f"ZIP分析失败: {str(e)}")
            return {"error": f"无法分析ZIP文件: {str(e)}"}

    def _is_code_file(self, filename: str) -> bool:
        """判断是否为代码文件"""
        code_extensions = ['.py', '.js', '.java', '.go', '.cpp', '.h', '.html', '.css', '.ts']
        return any(filename.endswith(ext) for ext in code_extensions)

    def _analyze_project_structure(self, project_dir: Path) -> Dict:
        """分析项目目录结构"""
        structure = {
            "total_files": 0,
            "file_types": {},
            "important_files": []
        }

        for file in project_dir.rglob("*"):
            if file.is_file():
                structure["total_files"] += 1
                file_ext = file.suffix.lower()
                structure["file_types"][file_ext] = structure["file_types"].get(file_ext, 0) + 1

                # 标记重要文件
                if file.name in ['package.json', 'requirements.txt', 'pom.xml', 'build.gradle']:
                    structure["important_files"].append(str(file.relative_to(project_dir)))

        return structure

    def _is_code_file(self, filename: str) -> bool:
        """判断是否为代码文件"""
        code_extensions = [
            '.py', '.js', '.java', '.go',
            '.cpp', '.h', '.html', '.css',
            '.ts', '.php', '.rb', '.swift'
        ]
        return any(filename.lower().endswith(ext) for ext in code_extensions)

    def _analyze_zip_structure(self, zip_ref: zipfile.ZipFile) -> Dict:
        """分析ZIP文件结构"""
        structure = {
            "total_files": 0,
            "file_types": {},
            "important_files": []
        }

        for file_info in zip_ref.infolist():
            if not file_info.is_dir():
                structure["total_files"] += 1
                file_ext = os.path.splitext(file_info.filename)[1]
                structure["file_types"][file_ext] = structure["file_types"].get(file_ext, 0) + 1

                # 标记重要文件
                if file_info.filename in ['package.json', 'requirements.txt', 'README.md']:
                    structure["important_files"].append(file_info.filename)

        return structure

    def _generate_zip_summary(self, analysis_results: Dict) -> Dict:
        """
        生成ZIP项目的综合分析报告

        返回结构:
        {
            "tech_stack": [],       # 技术栈列表
            "main_components": [],  # 主要组件
            "potential_issues": [], # 潜在问题
            "key_files": [],        # 关键配置文件
            "stats": {              # 统计信息
                "total_files": int,
                "code_files": int,
                "file_types": dict
            }
        }
        """
        summary = {
            "tech_stack": set(),
            "main_components": [],
            "potential_issues": [],
            "key_files": [],
            "stats": {
                "total_files": 0,
                "code_files": 0,
                "file_types": {}
            }
        }

        # 预定义技术栈映射
        TECH_STACK_MAP = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.kt': 'Kotlin',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.swift': 'Swift',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SASS'
        }

        # 预定义关键文件
        KEY_FILES = {
            'package.json': 'Node.js项目配置',
            'requirements.txt': 'Python依赖',
            'pom.xml': 'Java Maven配置',
            'build.gradle': 'Gradle配置',
            'dockerfile': 'Docker配置',
            'makefile': 'Makefile',
            'webpack.config.js': 'Webpack配置'
        }

        for filename, data in analysis_results.items():
            if filename.startswith('_'):  # 跳过元数据
                continue

            # 文件统计
            summary["stats"]["total_files"] += 1
            file_ext = os.path.splitext(filename)[1].lower()
            summary["stats"]["file_types"][file_ext] = summary["stats"]["file_types"].get(file_ext, 0) + 1

            # 识别技术栈
            if file_ext in TECH_STACK_MAP:
                summary["tech_stack"].add(TECH_STACK_MAP[file_ext])
                summary["stats"]["code_files"] += 1

            # 识别关键文件
            if filename.lower() in KEY_FILES:
                summary["key_files"].append(f"{filename} ({KEY_FILES[filename.lower()]})")

            # 分析代码内容
            if isinstance(data, dict) and 'analysis' in data and isinstance(data['analysis'], str):
                analysis_text = data['analysis'].lower()

                # 识别组件
                component_types = ['class', 'function', 'component', 'module', 'service']
                if any(comp in analysis_text for comp in component_types):
                    summary["main_components"].append(filename)

                # 识别问题
                issue_keywords = [
                    'issue', 'problem', 'vulnerability',
                    'risk', 'warning', 'deprecated', 'insecure'
                ]
                if any(kw in analysis_text for kw in issue_keywords):
                    summary["potential_issues"].append({
                        "file": filename,
                        "detail": data['analysis'][:200] + "..."  # 截取部分分析内容
                    })

        # 后处理
        return {
            "tech_stack": sorted(list(summary["tech_stack"])),
            "main_components": summary["main_components"][:10],  # 限制数量
            "potential_issues": summary["potential_issues"][:5],
            "key_files": summary["key_files"],
            "stats": {
                "total_files": summary["stats"]["total_files"],
                "code_files": summary["stats"]["code_files"],
                "file_types": dict(sorted(
                    summary["stats"]["file_types"].items(),
                    key=lambda x: x[1],
                    reverse=True
                ))
            }
        }
    def _safe_read_file(self, file_path: Path) -> Optional[str]:
        """安全读取文件内容（自动处理编码问题）"""
        encodings = ['utf-8', 'gbk', 'gb18030', 'big5', 'utf-16', 'latin1']

        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read(50000)  # 限制读取长度
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"文件读取错误 [{encoding}]: {file_path} - {str(e)}")
                break

        # 终极回退方案：二进制读取
        try:
            with open(file_path, 'rb') as f:
                return f.read(50000).decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"二进制读取失败: {file_path} - {str(e)}")
            return None

    def _analyze_file(self, file_path: Path, content: str) -> str:
        """分析单个代码文件"""
        # 检查缓存
        cache_key = hashlib.md5(content.encode('utf-8')).hexdigest()
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        try:
            # 构建分析提示
            file_ext = file_path.suffix
            prompt = f"""请分析以下{file_ext}代码文件，提供以下信息：
1. 主要功能
2. 关键函数/类
3. 潜在问题
4. 改进建议

代码内容：
{content[:20000]}"""

            response = self.client.chat.completions.create(
                model="deepseek-coder",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=2000
            )
            analysis = response.choices[0].message.content
            self.analysis_cache[cache_key] = analysis
            return analysis
        except Exception as e:
            logger.error(f"分析文件 {file_path} 时出错: {str(e)}")
            return f"分析失败: {str(e)}"

    # def chat(self, message: str, use_code_context: bool = True) -> str:
    #     """与系统对话，可选择是否使用代码上下文"""
    #     # 保存用户消息
    #     self.conversation_history.append({"role": "user", "content": message})
    #
    #     # 准备系统消息
    #     system_message = {
    #         "role": "system",
    #         "content": "你是一个专业的代码分析助手，可以查看代码库内容。"
    #     }
    #
    #     # 如果使用代码上下文且存在分析过的代码
    #     if use_code_context and self.code_context:
    #         # 找出最相关的代码文件
    #         relevant_files = self._find_relevant_files(message)
    #
    #         # 构建包含代码上下文的提示
    #         enhanced_message = self._enhance_with_context(message, relevant_files)
    #     else:
    #         enhanced_message = message
    #
    #     # 构建消息历史（最近的3轮对话）
    #     messages = [
    #         system_message,
    #         *self.conversation_history[-3:],
    #         {"role": "user", "content": enhanced_message}
    #     ]
    #
    #     # 发送请求
    #     response = self.client.chat.completions.create(
    #         model="deepseek-coder",
    #         messages=messages,
    #         temperature=0.7,
    #         max_tokens=2000,
    #         timeout=30.0
    #     )
    #
    #     reply = response.choices[0].message.content
    #     self.conversation_history.append({"role": "assistant", "content": reply})
    #     return reply

    def _find_relevant_files(self, question: str) -> List[Tuple[str, str]]:
        """找出与问题最相关的代码文件"""
        if not question or not self.code_context:
            return []

        # 提取问题中的关键词
        try:
            keyword_response = self.client.chat.completions.create(
                model="deepseek-coder",
                messages=[
                    {"role": "system", "content": "提取以下问题中的技术关键词"},
                    {"role": "user", "content": question}
                ],
                temperature=0.3,
                max_tokens=500
            )
            keywords = [
                kw.strip().lower()
                for kw in keyword_response.choices[0].message.content.split()
                if kw.strip()
            ]
        except Exception as e:
            print(f"提取关键词时出错: {str(e)}")
            keywords = [
                kw.strip().lower()
                for kw in question.split()
                if len(kw) > 3  # 忽略过短的词
            ]

        # 根据关键词匹配文件
        relevant_files = []
        for rel_path, data in self.code_context.items():
            try:
                content = data['content'].lower() if isinstance(data.get('content'), str) else ""
                analysis = data['analysis'].lower() if isinstance(data.get('analysis'), str) else ""

                # 计算匹配度
                match_score = sum(
                    1 for kw in keywords
                    if kw and (kw in content or kw in analysis)
                )

                if match_score > 0:
                    relevant_files.append((
                        rel_path,
                        f"匹配度: {match_score}, 路径: {rel_path}, 分析摘要: {str(data.get('analysis', ''))[:200]}"
                    ))
            except Exception as e:
                print(f"处理文件 {rel_path} 时出错: {str(e)}")
                continue

        # 按匹配度排序并返回前3个
        try:
            relevant_files.sort(
                key=lambda x: int(x[1].split("匹配度: ")[1].split(",")[0]),
                reverse=True
            )
        except Exception as e:
            print(f"排序相关文件时出错: {str(e)}")
            relevant_files = relevant_files[:3]  # 保持原始顺序但限制数量

        return relevant_files[:3]

    def _enhance_with_context(self, question: str, relevant_files: List[Tuple[str, str]]) -> str:
        """用代码上下文增强问题"""
        if not relevant_files:
            return question

        # 构建上下文信息
        context_lines = []
        for i, (rel_path, info) in enumerate(relevant_files, 1):
            try:
                match_score = info.split("匹配度: ")[1].split(",")[0]
                path = info.split("路径: ")[1].split(",")[0]
                context_lines.append(f"{i}. 匹配度: {match_score}, 文件: {path}")
            except:
                context_lines.append(f"{i}. 文件: {rel_path}")

        context_str = "\n".join(context_lines)

        # 添加实际代码片段
        code_snippets = []
        for rel_path, _ in relevant_files[:2]:  # 只取前两个文件添加详细代码
            data = self.code_context.get(rel_path, {})
            content = data.get('content', '')[:1000]  # 限制代码长度
            if content:
                code_snippets.append(f"\n\n文件: {rel_path}\n代码片段:\n{content}")

        return (
            f"问题: {question}\n"
            f"相关文件:\n{context_str}\n"
            f"{''.join(code_snippets)}"
        )
    def interactive_chat(self):
        """启动交互式对话"""
        print("代码分析对话系统已启动(输入'退出'结束)")
        print("可用命令:")
        print("  /context - 显示当前代码上下文")
        print("  /nocode - 不使用代码上下文")

        use_context = True

        while True:
            try:
                user_input = input("\n用户: ").strip()
                if user_input.lower() in ["退出", "exit", "quit"]:
                    break

                # 处理命令
                if user_input.startswith('/'):
                    if user_input.lower() == '/context':
                        print("\n当前代码上下文:")
                        for rel_path in self.code_context:
                            print(f"- {rel_path}")
                        continue
                    elif user_input.lower() == '/nocode':
                        use_context = False
                        print("已禁用代码上下文模式")
                        continue
                    else:
                        print("未知命令")
                        continue

                # 正常聊天
                response = self.chat(user_input, use_code_context=use_context)
                print(f"\n助手: {response}")

                # 自动重置上下文使用
                use_context = True

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"发生错误: {e}")

    def generate_summary(self, analysis_results: Dict) -> str:
        """生成代码库摘要"""
        summary_prompt = """
        请根据以下代码分析结果生成一份综合摘要:
        - 主要技术栈
        - 代码结构特点
        - 潜在问题
        - 改进建议

        分析结果:
        {analysis_results}
        """.format(analysis_results=json.dumps(analysis_results, indent=2)[:10000])

        response = self.client.chat.completions.create(
            model="deepseek-coder",
            messages=[{"role": "user", "content": summary_prompt}],
            temperature=0.4,
            max_tokens=2000
        )
        return response.choices[0].message.content

    def find_issues(self, issue_type: str = "security") -> Dict:
        """定位特定类型问题"""
        prompt = f"""
        请在我的代码库中查找所有{issue_type}相关问题，并按严重性分类:
        1. 高危问题
        2. 中危问题
        3. 建议改进

        返回格式:
        - 文件名
        - 问题描述
        - 修复建议

        可用分析数据:
        {json.dumps(self.code_context, indent=2, default=str)[:15000]}
        """

        response = self.client.chat.completions.create(
            model="deepseek-coder",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=2000
        )
        return response.choices[0].message.content


if __name__ == "__main__":
    # 初始化系统
    system = CodeAnalysisChatSystem(api_key="sk-a44ec9c560504eb7a151b3ea9c5794e9")

    # 分析ZIP文件
    zip_path = "../loginfront-main.zip"
    print(f"开始分析 {zip_path}...")
    analysis_results = system.analyze_zip(zip_path)

    # 生成摘要
    summary = system.generate_summary(analysis_results)
    print("\n项目摘要:")
    print(summary)

    # 查找安全问题
    security_issues = system.find_issues("security")
    print("\n安全问题:")
    print(security_issues)

    # 进入对话模式
    print("\n进入对话模式(可询问代码相关问题):")
    system.interactive_chat()