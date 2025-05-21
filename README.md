# BeeLine Web Scheduling Console

BeeLine是一个基于FastAPI的Python脚本管理平台，提供Web界面来管理Python脚本的执行、调度和监控。

## 版本更新
### 版本更新使用说明
- 直接拉取/下载新版本全部文件完整覆盖原文件即可，除非特殊说明，否则不会丢失配置数据库，不会影响此前添加的脚本/任务

### 版本 1.0.5 25/05/21 【关联文件需要新增数据表，所以更新此版本**需要删除beeline.db重新添加脚本和任务**】
- 新增“运行日志”页面显示运行任务耗时和输出/错误区域最大高度，超出将显示进度条
- 修复“任务调度”页面不显示任务描述的BUG
- 新增“环境变量”页面没有环境变量时的提示
- 修复脚本新建/上传时，不填写描述就上传/创建失败的BUG
- “脚本管理”页面新增“关联文件”功能，用于上传脚本需要用到的json、yaml等配置文件（关联文件仅用于区分由哪个脚本使用，但不和脚本绑定）
- 新增关联文件编辑模态框，可以在线编辑文本模式的关联文件
- 修复删除脚本时的关联任务处理问题，确保删除脚本时同时清理相关任务和日志以及关联文件
- 优化任务列表页面，自动处理已删除脚本的关联任务（兜底操作）
- 修复脚本执行时的工作目录问题，确保脚本可以正确访问同级目录（/scripts）的文件
- 优化子进程执行环境，避免影响主进程工作目录
- 完善包管理功能，新增POST提交/packages路由，现可通过Web界面安装和卸载Python包。
- 优化安装包时的提示。（后续可能考虑加入WebSocket来实时显示安装进度）

## 功能特点

- 脚本管理：上传、编辑和删除Python脚本
- 任务调度：支持手动执行和cron定时执行
- 包管理：管理Python包依赖
- 环境变量：管理Python脚本环境变量
- 运行日志：查看任务执行日志
- 美观的Web界面：使用Tailwind CSS构建的现代化界面

## 运行截图
![Image 1](https://kycloud3.koyoo.cn/202505209f18520250520162913141.png)
![Image 2](https://kycloud3.koyoo.cn/202505205ef8d202505201629108982.png)
![Image 3](https://kycloud3.koyoo.cn/20250520410c120250520162913711.png)
![Image 4](https://kycloud3.koyoo.cn/2025052086834202505201629119487.png)
![Image 5](https://kycloud3.koyoo.cn/202505207a7e6202505201629131071.png)
![Image 6](https://kycloud3.koyoo.cn/20250520b5633202505201629119851.png)
![Image 7](https://kycloud3.koyoo.cn/202505203add020250520162912269.png)
![Image 8](https://kycloud3.koyoo.cn/202505209599f202505201629123296.png)

## 安装

1. 下载项目：
```bash
git clone https://github.com/3iXi/beeline.git
```

2. 安装Python（以Windows为例，建议安装Python 3.6以上版本）

     a. **访问Python官网下载页面**  
        📎 [Python Windows下载页面](https://www.python.org/downloads/windows/)

     b. **选择版本**  
        - 在"Stable Releases"部分找到Python 3.11.x（建议选择3.10-3.12版本）

     c. **下载安装程序**  
        - 下载Windows installer（64位系统选择`Windows Installer (64-bit)`）

     d. **运行安装程序**  
        - 双击运行下载的安装程序（如`python-3.11.9-amd64.exe`）

     e. **重要安装步骤**  
        ✅ 勾选"Add Python 3.11 to PATH"  
        ✅ 选择"Customize installation"  
        ✅ 在可选功能中勾选：
          - "pip"
          - "py launcher"

     f. **完成安装**  
        - 点击"Install"按钮等待安装完成
        - 安装完成后可在CMD命令提示符中验证：  
          ```
          python --version
          ```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

## 运行

```bash
python main.py
```

访问 http://localhost:8000 即可打开BeeLine Web控制台。

默认管理员账号（登录后可在系统设置中修改）：
- 用户名：admin
- 密码：admin

## 项目结构

```
beeline/
├── beeline.db           # 配置数据库（首次运行main.py自动生成）
├── main.py              # 主程序入口
├── models.py            # 数据库模型
├── requirements.txt     # 项目依赖
├── scheduler.py         # 调度执行
├── static/              # 静态文件
├── templates/           # HTML模板
└── scripts/             # 用户脚本目录
```

## 注意事项

开启HTTPS需要在`main.py`中修改188行附近代码，将secure=True取消注释
```bash
        response.set_cookie(
            key="session_id",
            value=session_id,
            expires=timedelta(days=7),
            httponly=True,
            secure=True,
            samesite="Strict"
        )
```
