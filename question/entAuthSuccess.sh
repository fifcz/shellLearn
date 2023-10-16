#!/bin/bash

# 读取txt表格
while IFS='|' read -r credit_code filepath region year month status; do
    # 跳过表头
    if [[ $credit_code == "credit_code" ]]; then
        continue
    fi

    # 去除空格
    filepath=$(echo "${filepath}" | tr -d ' ')
    region=$(echo "${region}" | tr -d ' ')
    year=$(echo "${year}" | tr -d ' ')
    month=$(echo "${month}" | tr -d ' ')

    # 替换文件路径中的/nas/为/nas-share/images/
    filepath=${filepath//\/nas\//\/nas-share\/images\/}

    # 构建目标文件夹路径
    destination_folder="/data/${year}/${month}/${region}"

    # 检查目标文件夹是否存在，如果不存在则创建
    if [ ! -d "$destination_folder" ]; then
        mkdir -p "$destination_folder"
    fi

    # 获取文件名
    filename=$(basename "$filepath")

    # 构建目标文件路径
    destination_path="${destination_folder}/${filename}"

    # 复制文件到目标文件夹
    cp "$filepath" "$destination_path"
done < ent.txt
