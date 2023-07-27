# Memory Information Provider

- Application that manages same or differnet kinds of resources among the clients
- The clients are simulated by seperate threads
- If the `avoid-flag` is set to 1, deadlock avoidance is applied to manage the resources
- If the `avoid-flag` is set to 0, deadlock detection is applied and the occuring deadlocks can be seen
- Banker's Algorithm is used as deadlock avoidance algorithm
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

-
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

##### Example proctopk run

```
$ make
$ ./myapp 1
```
