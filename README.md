# Memory Information Provider

- Application that provides memory information (physical and virtual) about different processes such as, memory mappings, frame information, page frame number and more
- `<PFN>` stands for Page Frame Number
- `<PID>` stands for Process ID
- `<VA>` stands for Virtual Address
- All the addresses can be provided both in decimal and hexadecimal format
- The application is developed on Linux operating system using C programming language

## Contents

- Project4.pdf (Project Description)
- pvm.c (Source File)
- Makefile (Makefile to Compile the Project)

## How to Run

- cd to the project directory

##### Compilation and linking

```
$ make
```

##### Recompile

```
$ make clean
$ make
```

##### Running the program with options

```
$ ./pvm -frameinfo <PFN>
```

```
$ ./pvm -memused <PID>
```

```
$ ./pvm -mapva <PID> <VA>
```

```
$ ./pvm -pte <PID> <VA>
```

```
$ ./pvm -maprange <PID> <VA1> <VA2>
```

```
$ ./pvm -mapall <PID>
```

```
$ ./pvm -mapallin <PID>
```

```
$ ./pvm -alltablesize <PID>
```

##### Example runs for the program with options

```
$ make
$ ./pvm -frameinfo 10
```

```
$ make
$ ./pvm -memused 1
```

```
$ make
$ ./pvm -mapva 3 0x000009
```

```
$ make
$ ./pvm -pte 3 9
```

```
$ make
$ ./pvm -maprange 3 0x000009 100
```

```
$ make
$ ./pvm -mapall 5
```

```
$ make
$ ./pvm -mapallin 1
```

```
$ make
$ ./pvm -alltablesize 17
```
