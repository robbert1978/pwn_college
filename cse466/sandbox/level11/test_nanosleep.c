#include <stdio.h>
#include <time.h>

int main()
{
/*
struct __kernel_timespec {
	__kernel_time64_t       tv_sec;                 // seconds
	long long               tv_nsec;                // nanoseconds 
};.  
*/
   long long req[2]={5,0};
   if(nanosleep((struct timespec *)req , NULL) < 0 )   
   {
      printf("Nano sleep system call failed \n");
      return -1;
   }

   printf("Nano sleep successfull \n");

   return 0;
}