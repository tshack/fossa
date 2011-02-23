#include <stdio.h>
#include <string.h>
//#include "libcuzmem.h"
#include "plans.h"
#include "context.h"


void
test_planfile (void)
{
    char* buffer;
    cuzmem_plan *plan = NULL;
    cuzmem_plan *curr = NULL;

    plan = read_plan ("plastimatch", "foobar");
    curr = plan;

    write_plan (plan, "plastimatch", "foobaz");
}

void
test_context (void)
{
    CUZMEM_CONTEXT context;
    
//    create_context();

    context = get_context();

    printf ("plan_name[] : %s\n", context->plan_name);
    printf ("start_time  : %lu\n", context->start_time);
    printf ("best_time   : %lu\n", context->best_time);

    destroy_context ();
}

int
main (void)
{

//    test_planfile ();
    test_context ();

    return(0);
}
