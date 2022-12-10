
#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>

TEST(test_uir, test_uir_1)
{
    printf("-----------begin----------\n");
    printf("-----------end------------\n");
}

int
main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, const_cast<char **>(argv));
    return RUN_ALL_TESTS();
}
