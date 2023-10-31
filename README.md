<h1 align="center">HWIDex (WIP)</h1>
<br>
<p align="center">
<!--<img src="assets/banner.jpg" align="center" width="500" title="VMAware">-->
<br>
<img alt="GitHub Workflow Status (with event)" align="center" src="https://img.shields.io/github/actions/workflow/status/GoddessZex/HWIDex/cmake-multi-platform.yml">
<img alt="GitHub" align="center" src="https://img.shields.io/github/license/GoddessZex/HWIDex">
</p>

**HWIDex** is a work in progress C++ library designed for fetching HWID value hashes based on the current user's hardware and system information. It is designed for anti-cheat, anti-ban bypassing, and many other use cases as well.



## Example 🧪
```cpp
#include "hwidex.h"
#include <iostream>

int main() {
    std::cout << GetHWID() << "\n";
    return 0;
}
```


## Credits ✒️
    - [GoddessZex](https://github.com/GoddessZex)
    - [kernelwernel](https://github.com/kernelwernel)