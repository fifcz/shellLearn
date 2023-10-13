#!/bin/bash

cd /czgit/shelllearn/  # 切换到 /czgit/shelllearn/ 目录
git stash  # 暂存更改
git pull  # 拉取最新代码
chmod +x /czgit/shelllearn/infolevel  # 添加可执行权限
./other.sh  # 运行 ./other.sh 脚本

