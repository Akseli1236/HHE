In order to use the crypto++ this command must be run: sudo apt-get install libcrypto++-dev

## Running
On linux Ubuntu The code should work with just navigatin to build folder and running "./own-hhe"
if not then delete build folder and do:
In the terminal, `cd` into the project's directory, then run
- `cmake -S . -B build -DCMAKE_PREFIX_PATH=libs/seal`  
- `cmake --build build`  
- Then the project can be run in the build folder with the "./own-hhe"
