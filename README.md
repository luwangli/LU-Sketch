# LU-Sketch
a new sketch for top-k finding



### Requirement

- Install the p4 behavioral model (follow the steps [here](https://github.com/p4lang/behavioral-mode))
- Install the p4 compiler ([details](https://github.com/p4lang/p4c))

- g++ >= 5.4

- make >= 4.1

  

### Compile

You can build bmv2 switch by

```
make clean
make
```

### Run

- we provide two pcap file in data. Send packets to the bmv2 switch with the python script 

  ```
  ./send_traffic_pcap.py
  ```

  

- Dump the register table of LU-Sketch via CLI of BMV2

  - enter the CLI

    ```
    simple_Switch_CLI 
    ```

    

  - dump register tables in CLI

    ```
    register_read
    ```

    

    