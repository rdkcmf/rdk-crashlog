#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "crashlog.h"

#define END_OF_SIG_LIST 0
#define CRASHLOG_DIR_NAME "/opt/logs/"
#define LOG_FILE_NAME "/opt/logs/core_log.txt"
#define FILE_EXT_LEN 5    // file extension is .txt
static char filename_extension[FILE_EXT_LEN] = { '.', 't', 'x', 't', 0 };

int SigsToHandle[] = {
    SIGSEGV,
    END_OF_SIG_LIST };

// the following should be filenames found in the /proc/<PID> directory
char *dumpfilename[] = {
    "cmdline",
    "maps",
    NULL };     // last element must remain NULL


static void __attribute__((constructor)) create_logger( void )
{
    struct sigaction act;
    int i;

    sigemptyset( &act.sa_mask );
    act.sa_handler = (void*)log_crash;
    act.sa_flags = SA_RESTART;

    for( i=0; SigsToHandle[i] != END_OF_SIG_LIST; i++ )
    {
        sigaction( SigsToHandle[i], &act, NULL );
    }
}



static void log_crash( int signum, void *context )
{
    struct tm *ptimeinfo;
    struct sigaction act;
    time_t rawtime;
    FILE *fpout, *fpin;
    pid_t mypid;
    int i;
    char indir[80];
    char infile[100];
    char outfile[100];
    char instr[100];
    char *pstr;
    char *signame = NULL;
    char *ptmp = NULL;
 
    mypid = getpid();

    snprintf( indir, sizeof( indir ), "/proc/%d/", (int)mypid );    // indir should contain /proc/<PID NUMBER>

    snprintf( infile, sizeof( infile ), "%scomm", indir );    // infile = path and filename "comm"
    if( (fpin=fopen( infile, "r" )) != NULL )
    {
        pstr = fgets( instr, sizeof( instr ) - 1, fpin );    // instr should contain the command name that triggered the crash
        fclose( fpin );
        if( pstr != NULL )    // fgets returned a valid pointer to something
        {
            ptmp = pstr;
            while( *ptmp++ )
            {
                if( isprint( *ptmp ) == 0 )
                {
                    *ptmp = 0;    // if it's not printable then terminate string
                    break;
                }
            }
            if( signum < _NSIG )
            {
                signame = strdup( sys_siglist[signum] );
                if( signame != NULL )
                {
                    ptmp = signame;
                    while( *ptmp++ )
                    {
                        if( *ptmp == 0x20 )    // convert space character to '_'
                        {
                            *ptmp = '_';
                        }
                        else
                        {
                            *ptmp = toupper( *ptmp );
                        }
                    }
                }
            }
             
            ptmp = signame;    // remember existing value of signame for free check below
            if( signame == NULL )
            {
                signame = "UNKNOWN";
            }
            snprintf( outfile, sizeof( outfile ) - FILE_EXT_LEN, "%scrashlog_%s_%s", CRASHLOG_DIR_NAME, signame, instr );    // outfile = log path, signal name,  plus the string found in "comm" file
            strncat( outfile, filename_extension, FILE_EXT_LEN - 1 );    // add the file extension
            if( ptmp != NULL )
            {
                free( signame );    // signame was created by the call to strdup above
            }
            if( (fpout=fopen( outfile, "w" )) != NULL )			// create crash log file to write the required output
            {
                time( &rawtime );    // write GMT time to log file
                ptimeinfo = gmtime( &rawtime );
                signame = asctime( ptimeinfo );    // reuse signame as a temporary pointer
                if( signame != NULL )
                {
                    ptmp = signame;
                    while( *ptmp++ )
                    {
                        if( *ptmp == '\n' )
                        {
                            *ptmp = 0;
                            break;
                        }
                    }
                    fprintf( fpout, "Crash time: %s GMT\n", signame);
                }

                if( *pstr )
                {
                    fprintf( fpout, "Command: %s\n", pstr );  // pstr should already point to instr from fgets call above, instr should contain crashed command name
                }
                for( i=0; dumpfilename[i] != NULL; i++ )
                {
                    snprintf( infile, sizeof( infile ), "%s%s", indir, dumpfilename[i] );    // infile = path and filename from dumpfilename
                    fprintf( fpout, "Filename: %s\n", infile );
                    if( (fpin=fopen( infile, "r" )) != NULL )
                    {
                        while( (pstr=fgets( instr, sizeof( instr ) - 1, fpin )) != NULL )    // start reading lines from file
                        {
                            fprintf( fpout, "%s", pstr );    // write the line to the output file
                        }
                        fclose( fpin );
                        fprintf( fpout, "\n" );
                    }
                    fprintf( fpout, "\n" );
                }
                fclose( fpout );

                if( (fpout=fopen( LOG_FILE_NAME, "a" )) != NULL )			// add a line to a log file saying we created a crashlog
                {
                    fprintf( fpout, "%s, Creating stacktrace file: %s\n", signame, outfile );    // signame should still have the date/time
                    fclose( fpout );
                }
                else
                {
                    fprintf( stderr, "Could not open %s\n", LOG_FILE_NAME );
                }
            }
            else
            {
                fprintf( stderr, "Could not open %s for writing\n", outfile );
            }
        }
    }

    sigemptyset( &act.sa_mask );
    act.sa_handler = SIG_DFL;
    act.sa_flags = 0;
    sigaction( signum, &act, NULL );
    raise( signum );
}
