# Reverse Engineering 

### Points:
1. ebp+0xc is a 4 byte pointer. (Eg: char* str)
`mov eax, dword [ebp+0xc]`
2. ebp+0x4, ebp+0x8: are the arguments of the function. 
3. 0 is also `null`
4. `==` operator always evaluates to 1 if the 2 values are equal
### Other Common C Patterns
1. `#define TEST 2.3`
```
add     eax, 0x2e0a {GLOBAL_OFFSET_TABLE}
```
2. Modulo operator:  
```C
#include<stdio.h>
#include<stdlib.h>

int re_this(int num1, int num2) {
    return ((num1 + num1) % 6);
}

int main(){
    //Random arguments
    return re_this(6, 3);
}
```
equivalent to:
```C
push    ebp {__saved_ebp}
mov     ebp, esp {__saved_ebp}
call    __x86.get_pc_thunk.ax
add     eax, 0x2e7e  {_GLOBAL_OFFSET_TABLE_}
mov     eax, dword [ebp+0x8 {arg1}]
lea     ecx, [eax+eax]
mov     edx, 0x2aaaaaab
mov     eax, ecx
imul    edx
mov     eax, ecx
sar     eax, 0x1f
sub     edx, eax
mov     eax, edx
add     eax, eax
add     eax, edx
add     eax, eax
sub     ecx, eax
mov     edx, ecx
mov     eax, edx
pop     ebp {__saved_ebp}
retn     {__return_addr}
```

### Floating Point Reverse Engineering 

https://home.deec.uc.pt/~jlobo/tc/artofasm/ch14/ch144.htm#HEADING4-37

**Note**
1. There is no usage of `push` before functiona calls. `fld` is used instead. 

**Examples:**   

`var_8 = argc `
```C
fld     dword [ebp+0x8 {argc}]   //Load floating point value
fstp    dword [ebp-0x4 {var_8}]  //Store floating point value (that you just loaded) and pop. 
```

`func(1.0f, 2.0f)`
where func accepts two float values.
```
lea     esp, [esp-0x4]
fstp    dword [esp {var_8}]

lea     esp, [esp-0x4]
fstp    dword [esp {var_c}]

```
1. Declaring and initialising `float a = 1.1` results in a fild (load integer) operation.
What you need to do is directly use floating numbers in function calls to avoid this. 

2. This is equivalent to `floating number arg2 - floating number eax-0x1`
```
fld     dword [ebp+0xc {arg2}]
fld     dword [eax-0x1]
fsubp   st1
```

### Sizing and Types
`qword` - long int/float/ (%lf)
`imul` - signed integer
`byte` - char

**Examples:**  
```C
double reme(int n1, int n2) {
    return n1 * n2 * 1.4;
}
```
equivalent to:
```C
add     eax, 0x2e20  {_GLOBAL_OFFSET_TABLE_}   // a constant value  
mov     edx, dword [ebp+0x8 {arg1}]            
imul    edx, dword [ebp+0xc {int_arg2}]        // imul means arg2 is a signed int. Multiple arg1 * arg2
mov     dword [ebp-0x4 {var_8}], edx           // var (ebp-0x4) = arg1 * arg2 
fild    dword [ebp-0x4]                        // fild means var is either a word, dwrod or qword. Loaded into memory
fld     qword [eax-0x1fd4]                     // load a qword (a float in this case we can see from the next instruction)
fmulp   st1                                    // multiple (int/long) arg1 * int arg2 * float value (0.5)
```



## Signed and Unsignedness
imul - for unsigned multiplication  
mul = signed multiplication

`edx = edx * arg2`
```
imul    edx, dword [ebp+0xc {arg2}]
```


### C Program Template 

```C
#include <stdio.h>

void func(char *dst, char* src) {
    
}

int main(int argc, char* argv[], char* envp[]) {

}
```

