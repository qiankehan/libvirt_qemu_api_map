# Introduction
The script is to generate the **libvirt APIs** to qemu interface\(**qmp**, 
**guest agent commands**\) mappings.

# Requirement
```
python3 >= 3.7
cscope
```

# Usage
1. Download libvirt source code. For example, download libvirt source code to `~/libvirt`
2. Run the script:
    1. Generate the **qemu QMP** to **libvirt API** mapping csv:
    ```sh
    ./libvirt_qemu_map -s ~/libvirt -o qmp.csv -m qmp
    ```
    2. Generate the **qemu guest agent command** to **libvirt API** mapping csv:
    ```sh
    ./libvirt_qemu_map -s ~/libvirt -o ga.csv -m ga
    ```
