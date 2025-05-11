import chardet
import json
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


def safe_read_file(file_path: str, max_length: int = 5000) -> str:
    """安全读取文件内容，自动检测编码"""
    try:
        if not Path(file_path).exists():
            logger.warning(f"文件不存在: {file_path}")
            return "[文件不存在]"

        # 二进制模式读取检测编码
        with open(file_path, 'rb') as f:
            raw_data = f.read(max_length)
            if not raw_data:
                return "[空文件]"

            try:
                encoding = chardet.detect(raw_data)['encoding'] or 'utf-8'
                # 尝试解码
                return raw_data.decode(encoding)
            except UnicodeDecodeError:
                # 回退方案
                encodings = ['gb18030', 'gbk', 'utf-8', 'latin-1']
                for enc in encodings:
                    try:
                        return raw_data.decode(enc)
                    except UnicodeDecodeError:
                        continue

        return "[无法解码文件内容]"

    except Exception as e:
        logger.error(f"读取文件失败: {file_path} - {str(e)}", exc_info=True)
        return f"[文件读取错误: {str(e)}]"


def safe_json_loads(data):
    """安全解析JSON数据"""
    if data is None:
        return {}
    try:
        return json.loads(data) if isinstance(data, (str, bytes, bytearray)) else data
    except json.JSONDecodeError:
        logger.warning(f"JSON解析失败，原始数据: {str(data)[:200]}")
        return {}