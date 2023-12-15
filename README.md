In order to use the crypto++ this command must be run: sudo apt-get install libcrypto++-dev

## Running
The code should work with just navigatin to build folder and running "./own-hhe"
if not then
In the terminal, `cd` into the project's directory, then run
- `cmake -S . -B build -DCMAKE_PREFIX_PATH=libs/seal`  
- `cmake --build build`  
- Then the project can be run in the build folder with the "./own-hhe"
