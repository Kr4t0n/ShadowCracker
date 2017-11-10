#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

struct userinfo_struct {
    char user[128];
    char salt[128];
    char crypt_passwd[128];
};

int parse_shadowline(char *shadow_line, struct userinfo_struct *parse_result);
int dict_crack(FILE *dict_fq, struct userinfo_struct userinfo);

int parse_shadowline(char *shadow_line, struct userinfo_struct *parse_result) {
    char *p, *q;

    if (shadow_line == NULL) {
        printf("Error shadow_line input!\n");
        return -1;
    }
    // Extract each line in the shadow file with the proper
    // userinfo_struct format
    p = shadow_line;
    q = strchr(p, ':');

    if (!q) {
        printf("0x001, Not userinfo format\n");
        return -1;
    }
    // Extract the username from the line of shadow file
    strncpy(parse_result -> user, p, q - p);
    parse_result -> user[q - p] = '\0';
    p = q + 1;

    if (strncmp(p, "$1$", 3) == 0) {
        printf("Password encrypted by md5 algorithm!\n");
    }
    else if (strncmp(p, "$5$", 3) == 0) {
        printf("Password encrypted by SHA-256 algorithm!\n");
    }
    else if (strncmp(p, "$6$", 3) == 0) {
        printf("Password encrypted by SHA-512 algorithm!\n");
    }
    else {
        printf("0x002, Not userinfo format!\n");
        return -1;
    }

    q = strchr(p + 3, '$');
    if (!q) {
        printf("0x003, Not userinfo format!\n");
        return -1;
    }
    strncpy(parse_result -> salt, p, q - p + 1);
    
    parse_result -> salt[q - p + 1] = '\0';
    p = q + 1;
    q = strchr(p, ':');
    if (!q) {
        printf("0x004, Not userinfo format!\n");
        return -1;
    }
    strncpy(parse_result -> crypt_passwd, p, q - p);
    parse_result -> crypt_passwd[q - p] = '\0';
    return 0;
}

int dict_crack(FILE *dict_fq, struct userinfo_struct userinfo) {
    char *hash_check;
    int success_flag = 0;
    char one_word[256];
    char hash_code[256];

    strcpy(hash_code, strcat(userinfo.salt, userinfo.crypt_passwd));
    fseek(dict_fq, 0, SEEK_SET);
    while ((fscanf(dict_fq, "%s", one_word)) != EOF) {
        hash_check = (char *) crypt(one_word, userinfo.salt);
        if (strcmp(hash_code, hash_check) == 0) {
            success_flag = 1;
            printf("Password for user %s is %s\n", userinfo.user, one_word);
            break;
        }
    }

    return success_flag;
}

int main(int argc, char *argv[]) {
    FILE *shadow_fq;
    FILE *dict_fq;
    char shadow_line[256];
    struct userinfo_struct userinfo;
    int SUCCESS;

    if (argc != 3) {
        printf("Input format error! Usage as: \n");
        printf("%s shadow_file dict_file\n", argv[0]);
        exit(1);
    }

    if ((shadow_fq = fopen(argv[1], "r")) == NULL) {
        printf("Cannot open shadow file!\n");
        exit(1);
    }
    if ((dict_fq = fopen(argv[2], "r")) == NULL) {
        printf("Cannot open dict file!\n");
        exit(1);
    }
    while ((fscanf(shadow_fq, "%s", shadow_line)) != EOF) {
        if (parse_shadowline(shadow_line, &userinfo) != 0) {
            continue;
        }
        if (dict_crack(dict_fq, userinfo) == 1) {
            SUCCESS = 1;
        }
        if (SUCCESS == 0) {
            printf("Sorry, no password cracked, please try another dictionary!\n");
        }
    }

    fclose(dict_fq);
    fclose(shadow_fq);
    return 0;
}
