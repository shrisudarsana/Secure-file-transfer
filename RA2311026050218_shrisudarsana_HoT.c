#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TOKENS 100
#define MAX_LINES 500
#define THRESHOLD 5.0

typedef struct {
    char token_name[50];
    int line_number;
} TokenLog;

typedef struct {
    int line_number;
    int token_count;
    float density;
    int is_token_heavy;
} LineAnalysis;

void analyze_token_density(TokenLog logs[], int n) {
    LineAnalysis results[MAX_LINES];
    int line_counts[MAX_LINES] = {0};
    int max_line = 0;
    int total_heavy = 0;
    int analyzed_lines = 0;

    // Reset counts
    for (int i = 0; i < MAX_LINES; i++) {
        line_counts[i] = 0;
    }

    // Aggregate tokens per line
    for (int i = 0; i < n; i++) {
        if (logs[i].line_number >= 0 && logs[i].line_number < MAX_LINES) {
            line_counts[logs[i].line_number]++;
            if (logs[i].line_number > max_line) max_line = logs[i].line_number;
        }
    }

    printf("\n--- Lexical Analysis: Token Density Report ---\n");
    printf("Line\tTokens\tDensity\t\tStatus\n");
    printf("----------------------------------------------\n");

    for (int i = 0; i <= max_line; i++) {
        if (line_counts[i] > 0) {
            // Populate results structure
            results[analyzed_lines].line_number = i;
            results[analyzed_lines].token_count = line_counts[i];
            results[analyzed_lines].density = (float)line_counts[i];
            results[analyzed_lines].is_token_heavy = (results[analyzed_lines].density > THRESHOLD);

            if (results[analyzed_lines].is_token_heavy) total_heavy++;

            printf("%d\t%d\t%.2f\t\t%s\n", 
                   results[analyzed_lines].line_number, 
                   results[analyzed_lines].token_count, 
                   results[analyzed_lines].density, 
                   results[analyzed_lines].is_token_heavy ? "[!] IS_TOKEN_HEAVY" : "NORMAL");
            
            analyzed_lines++;
        }
    }

    printf("----------------------------------------------\n");
    printf("Analysis Summary:\n");
    printf("  - Total Tokens Logged: %d\n", n);
    printf("  - Total Lines Analyzed: %d\n", analyzed_lines);
    printf("  - Heavy Lines Detected: %d\n", total_heavy);
    printf("  - Threshold Applied:    %.1f tokens/line\n", THRESHOLD);
    printf("----------------------------------------------\n");
}

int main() {
    // Sample Data: Lexical analysis logs (Token Name, Line Number)
    TokenLog logs[] = {
        {"INT", 1}, {"ID", 1}, {"ASSIGN", 1}, {"NUM", 1}, {"SEMI", 1}, {"PLUS", 1}, // 6 tokens on line 1
        {"IF", 2}, {"LPAREN", 2}, {"ID", 2}, {"GT", 2},                             // 4 tokens on line 2
        {"ID", 3}, {"ASSIGN", 3}, {"NUM", 3}, {"SEMI", 3}, {"MULT", 3}, {"ID", 3}, {"DIV", 3} // 7 tokens on line 3
    };
    
    int n = sizeof(logs) / sizeof(logs[0]);
    
    printf("RegNo: RA2311026050218\n");
    printf("Name: shrisudarsana\n");
    printf("Problem: Token Density Indicator\n");
    
    analyze_token_density(logs, n);
    
    return 0;
}
