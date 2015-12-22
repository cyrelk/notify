#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <regex.h>
#include <signal.h>
#include <syslog.h>

#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

extern char *optarg;
extern int optind, opterr, optopt;
extern int getopt(int argc, char * const argv[],
                  const char *optstring);

#define SUCCESS "SUCCESS"
#define FAILURE "FAILURE"
#define EVENT_SIZE      (sizeof (struct inotify_event))
#define MAX_PATH_LENGTH 4096
#define BUFFER_SIZE     (EVENT_SIZE + MAX_PATH_LENGTH) * 256

/**
   at this moment to compile use this:
   gcc -Wall -pedantic -ansi -o inswatcher inswatcher.c
 */

/** do not forget to declare i before use;
	yes i know, C99 permits inline declarations
	but i don't do C99 :)
 */
#define STRUPPER(str) \
  for(i=0;i<=strlen(str);i++){ \
	str[i]=toupper(str[i]);}

/**
   some neat tricks that i retrieved from "Deep C Secrets"
 */
#define STRCMP(s1,OR,s2) (strcmp(s1,s2) OR 0)

/**
   What we are watching for...
 */
struct watch_t {
  int      fd;
  int      wd;
  uint32_t mask;  /* FIXME: TODO */
  char    *folder_name; /* the absolute path of a folder */
};

/**
   these variables are global because
   they are used by the signal handler.
*/

/**
   the watches structure contains the information
   that we pass to inotify. It duplicates the inotify
   data but i prefer to keep control over that for
   this iteration of the code.
*/
struct watch_t  ** watches;
int watch_number = 0;

/**
   the inotify file descriptor
*/
int watch_fd;

/**
   the three communications pipes with the control processes
   the pipes are defined as file descriptors.
*/
char event_pipe_name[MAX_PATH_LENGTH + 1];
int event_pipe;

char command_pipe_name[MAX_PATH_LENGTH + 1];
int command_pipe;

char status_pipe_name[MAX_PATH_LENGTH + 1];
int status_pipe;

/** the name of the path where the fifo used
	between the dispatcher and the manager resides.
	inwatcher does not use that fifo by itself but it needs to know
	its location to format special events when launchers' fifos are deleted.
 */
char prefix_name[MAX_PATH_LENGTH + 1];

/**
   if this value is 1 then the program will just
   create the fifos then quit.
 */
int create_mode = 0;

/**
   initialize the inotify infrastructure and returns
   the file descriptor upon it.
 */
int init_watches( void )
{
  int fd;

  fd = inotify_init();
  if ( !fd ) {
	syslog( LOG_ERR, "ERROR: unable to initialize the inotify interface." );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  syslog( LOG_INFO, "INFO: inwatcher inotify file descriptor: %d", fd );

  return fd;
}

/**
   the signal handler that removes all the watches,
   closes the inotify infrastructure and the pipes.
 */
void destroy_watches( int signum )
{
  int i;
  int exit_error = EXIT_SUCCESS;

  syslog( LOG_INFO, "INFO: inwatcher destroys %d watches.", watch_number );

  for ( i = 0; i < watch_number; i++ )
	{
	  if ( inotify_rm_watch( watch_fd, watches[i]->wd ) )
		{
		  syslog( LOG_ERR, "ERROR: unable to deallocate a watch." );
		  exit_error = EXIT_FAILURE;
		}
	}

  if ( close( watch_fd ) < 0 )
	{
	  syslog( LOG_ERR, "ERROR: unable to close the inotify infrastructure." );
	  exit_error = EXIT_FAILURE;
	}

  if ( close( event_pipe ) < 0 )
	{
	  syslog( LOG_ERR, "ERROR: unable to close the event pipe." );
	  exit_error = EXIT_FAILURE;
	}

  if ( close( command_pipe ) < 0 )
	{
	  syslog( LOG_ERR, "ERROR: unable to close the command pipe." );
	  exit_error = EXIT_FAILURE;
	}

  if ( close( status_pipe ) < 0 )
	{
	  syslog( LOG_ERR, "ERROR: unable to close the status pipe." );
	  exit_error = EXIT_FAILURE;
	}

  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
  closelog();

  exit( exit_error );
}

struct watch_t * retrieve_watch_by_wd( const int wd )
{
  int i;
  for ( i = 0; i < watch_number; i++ )
	{
	  if ( watches[i]->wd == wd )
		return watches[i];
	}
  return NULL;
}

struct watch_t * retrieve_watch_by_folder_name( const char name [] )
{
  int i;
  for ( i = 0; i < watch_number; i++ )
	{
	  if ( strcmp( watches[i]->folder_name, name ) )
		return watches[i];
	}
  return NULL;
}

/**
   creates the watch and asks inotify to follow the folder
 */
struct watch_t * create_watch( const char name[] )
{
  struct watch_t * result;

  result = ( struct watch_t * ) malloc( sizeof ( struct watch_t ) );
  if ( result == NULL )
	{
	  syslog( LOG_ERR, "ERROR: unable to allocate memory for the watch structure." );
	  return (struct watch_t *) NULL;
	}

  result->fd = watch_fd;

  result->folder_name = ( char * ) malloc( strlen( name ) + 1 );
  strncpy( result->folder_name, name, strlen( name ) + 1 );

  result->wd = inotify_add_watch( watch_fd, name, IN_ALL_EVENTS );
  if ( -1 == result->wd ) {
	syslog( LOG_ERR, "ERROR: unable to create a watch; %m" );
	return (struct watch_t *) NULL;
  }

  return result;
}

/**
	creates a fifo if it does not exist in the first place.
 */
int make_fifo( const char pipe_name[] ) {
  struct stat buffer;

  if ( stat( pipe_name, & buffer ) )
	if ( mkfifo( pipe_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH ) )
	  {
		syslog( LOG_ERR, "ERROR: mkfifo %m for pipe: %s.", pipe_name );
		return EXIT_FAILURE;
	  }

  return EXIT_SUCCESS;
}

/**
   the control and messaging commands
 */

int send_message( int fd, const char message[] )
{
  ssize_t rc;

  rc = write( fd, message, strlen( message ) );
  if ( -1 == rc ) {
	syslog( LOG_ERR, "ERROR: send_message %m writing folder name." );
	return EXIT_FAILURE;
  }
  rc = write( fd, "\n", 1 );
  if ( -1 == rc ) {
	syslog( LOG_ERR, "ERROR: send_message %m writing newline." );
	return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int status( const char message[] )
{
  return send_message( status_pipe, message );
}

void add_folder( const char folder_name[] )
{
  int i, old_number;
  struct watch_t ** tmp;

  old_number = watch_number;
  watch_number++;

  tmp = ( struct watch_t ** ) malloc( watch_number * sizeof( struct watch_t * ) );
  if ( tmp == NULL )
	{
	  syslog( LOG_ERR, "ERROR: unable to allocate memory for the watches array." );
	  status( FAILURE );
	  return;
	}

  for ( i = 0; i < old_number ; i++ )
	{
	  tmp[i] = watches[i];
	}

  tmp[watch_number - 1] = create_watch( folder_name );
  if ( NULL == tmp[watch_number - 1] ) {
	syslog( LOG_ERR, "ERROR: unable to create the watch for folder %s.", folder_name );
	status( FAILURE );
	return;
  }

  watches = tmp;

  syslog( LOG_INFO, "INFO: add watch for folder %s.", watches[watch_number - 1]->folder_name );

  status( SUCCESS );
}

void remove_folder( const char folder_name [] )
{
  struct watch_t * watch;

  watch = retrieve_watch_by_folder_name( folder_name );
  if ( watch == NULL )
	{
	  syslog( LOG_ERR, "ERROR: unable to retrieves the watch." );
	  status( FAILURE );
	  return;
	}

  if ( -1 == inotify_rm_watch( watch_fd, watch->wd ) )
	{
	  syslog( LOG_ERR, "ERROR: unable to remove the watch for folder %s.", folder_name );
	  status( FAILURE );
	  return;
	}

  /* FIXME : compact the watches array and watch_number
   */

  free( watch );

  syslog( LOG_INFO, "INFO: remove watch for folder %s.", folder_name );

  status( SUCCESS );
}

void list_watches( void )
{
  int i;

  for ( i = 0; i < watch_number; i++ )
	{
	  status( watches[i]->folder_name );
	}
}

void add_fifo( const char fifo_name[] )
{
  /* FIXME: stat for the validity of the path
   */
  if ( 0 == strlen( fifo_name ) )
	{
	  syslog( LOG_INFO, "INFO: fifo name given was null, nothing to create." );
	  status( SUCCESS );
	}

  if ( EXIT_SUCCESS != make_fifo( fifo_name ) )
	{
	  syslog( LOG_ERR, "ERROR: unable to create the fifo." );
	  status( FAILURE );
	}

  status( SUCCESS );
}

char * remove_trailing_slash( char path[] )
{

  while ( path[strlen( path ) - 1] == '/' ) {
	path[strlen( path ) - 1 ] = 0;
  }
  return path;
}

/**
   write the name where the event fired to the event pipe
   an event has the form:
   path//'file'
   where 'file' may be the complete path of a fifo for example
   and path will be the prefix of the receiving fifo.
 */
int push_event( struct inotify_event * event, const int fifo_deleted )
{
  struct watch_t * watch;
  char pathname[MAX_PATH_LENGTH];

  watch = retrieve_watch_by_wd( event->wd );
  if ( watch == NULL ) {
	syslog( LOG_ERR, "ERROR: unable to retrieve the process for watcher: %d", event->wd );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  memset( pathname, 0, sizeof( pathname ) );
  if ( fifo_deleted )
	{
	  strcat( pathname, prefix_name );
	  remove_trailing_slash( pathname );
	  strcat( pathname, "/" ); /* two slashes with the starting one of the folder */
	  strcat( pathname, watch->folder_name );
	  remove_trailing_slash( pathname );
	  strcat( pathname, "/" );
	  strcat( pathname, event->name );
	}
  else
	{
	  strcat( pathname, watch->folder_name );
	  remove_trailing_slash( pathname );
	  strcat( pathname, "//" );
	  strcat( pathname, event->name );
	}

  if ( send_message( event_pipe, pathname ) )
	{
	  syslog( LOG_ERR, "ERROR: push_event %m writing folder name." );
	  return EXIT_FAILURE;
	}

  return EXIT_SUCCESS;
}

/**
	read the inotify events and send them to the client
	if they match the mask defined.
 */
void read_watch_fd( void )
{
  char buffer[BUFFER_SIZE];
  int first_byte = 0;
  struct inotify_event *event;
  int bytes_to_read;
  int bytes_read = 0, rc = 0;

  do {
	rc = ioctl( watch_fd, FIONREAD, &bytes_to_read );
  } while ( !rc && bytes_to_read < EVENT_SIZE );

  if ( -1 == rc ) {
	syslog( LOG_ERR, "ERROR: read_watch_fd %m when waiting in ioctl." );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  /* be careful as event sizes may vary; if I understand correctly
	 in some cases events may contains an array of chars that gives
	 the name of the touched file. So events are *not* always
	 EVENT_SIZE in length. the buffer is BUFFER_SIZE to accomodate
	 the different lengths of filenames.
  */
  bytes_read = read( watch_fd, buffer, bytes_to_read );

  /* printf( " -- %d to read and %d bytes read \n", bytes_to_read, bytes_read ); */

  if ( bytes_read < 0 ) {
	syslog( LOG_ERR, "ERROR: read_watch_fd read %m." );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  if ( bytes_read > 0 ) {
	do {
	  event = ( struct inotify_event * )( (char *) &buffer[0] + first_byte );

	  /* printf( "read event type: %x for watcher %x\n", event->mask, event->wd ); */

	  first_byte += sizeof( struct inotify_event ) + event->len;

	  /* FIXME: test for fifo having the name:
		 /folder/folder.fifo
		 else we risk to fire event for wrongly named user files.
	   */

	  if ( ( event->mask & IN_CLOSE_WRITE ) )
		{
		  if ( ! strstr( event->name, ".fifo" ) )
			push_event( event, 0 );
		}

	  if ( ( event->mask & IN_CREATE ) )
		{
		  if ( strstr( event->name, ".fifo" ) )
			push_event( event, 1 );
		}

	} while (first_byte <=  (int)(bytes_read - sizeof( struct inotify_event )));

  }

}

/**
   reads the command pipe and parses input using the following rules:
   command [parameter] \newline
   actual commands are:
   ADD /pathname/of/the/surveyed/folder\n
   REMOVE /pathname/of/the/surveyed/folder\n
   LIST\n
   ADDFIFO /pathname/of/the/fifo\n
 */
void parse_command_pipe( void )
{
  char buffer[BUFFER_SIZE];
  char * p = buffer;
  char c;
  char * command;
  char * argument;
  int i; /* for the STRUPPER macro*/

  memset( buffer, 0, sizeof( buffer ) );

  if ( 0 == read( command_pipe, (char *) &c, 1 ) )
	{
	  status( FAILURE );
	  return;
	}

  while ( c != '\n' )
	{
	  *p++ = c;
	  if ( 0 == read( command_pipe, (char *) &c, 1 ) )
		{
		  status( FAILURE );
		  return;
		}
	}
  *p = ' '; /* to help the parsing of the command by strtok */

  command = strtok( buffer, " " );
  STRUPPER( command );

  argument = strtok( (char *) NULL, " " );

  if ( STRCMP( command, ==,  "ADD" ) )
	add_folder( argument );
  else if ( STRCMP( command, ==, "REMOVE" ) )
	remove_folder( argument );
  else if ( STRCMP( command, ==, "LIST" ) )
	list_watches();
  else if ( STRCMP( command, ==, "ADDFIFO" ) )
	add_fifo( argument );
}

/**
   the main routine, listen for events from inotify, format and send
   the name of the folders impacted, and read the control pipe for
   commands from the controler scripts.
 */
int the_loop( void )
{
  fd_set read_fds;
  int max;
  struct timeval * read_timeout = NULL;
  int rc = 0;

  while ( 1 ) {

	FD_ZERO( &read_fds );
	FD_SET( watch_fd, &read_fds );
	FD_SET( command_pipe, &read_fds );

	if ( watch_fd > command_pipe )
	  max = watch_fd;
	else
	  max = command_pipe;

	/* we wait indefinitely for data coming into one of our pipe
	 */
	rc = select( max + 1, &read_fds, NULL, NULL, read_timeout );

	if ( rc < 0 ) {
	  syslog( LOG_ERR, "ERROR: select() %m in the loop." );
	  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	  closelog();
	  exit( EXIT_FAILURE );
	} else if ( rc == 0 ) {
	  /* timeout, should never happened */
	  continue;
	}

	if ( FD_ISSET( watch_fd, &read_fds ) )
	  read_watch_fd();

	if ( FD_ISSET( command_pipe, &read_fds ) )
	  parse_command_pipe();

  }

  return EXIT_SUCCESS;
}

void display_usage(void)
{
  puts("usage: inwatcher [-i] [-h] -e fifo [-c fifo -s fifo -p prefix].\n\n"
	   "\twhere '-i' asks inwatcher to create the '-e fifo' then quit.\n"
	   "\t      in that case '-e fifo' may be *any* named pipe to create.\n");
  puts("\twhere '-e fifo' is the path of the named pipe used to send events.\n"
	   "\twhere '-c fifo' is the path of the named pipe used for control.\n"
	   "\twhere '-s fifo' is the path of the named pipe used for returning status.\n"
	   "\twhere '-p prefix' is the path of the named pipe used between the dispatcher\n"
	   "\t      and the manager of the launchers' fifos.\n");
  puts("\tonce launched as a daemon the commands will be sent through\n"
	   "\tthe pipes defined by the '-c' and '-s' options.\n"
	   "\t-h to display this message.\n\n");
}

/**
   load all the arguments from the command line into the
   arguments structure. In particular load all the couples
   (folder, process) that will be extend later to get
   full pathname by walk_folders.
 */
int load_arguments( int argc, char ** argv )
{
  int opt, len;

  while ( ( opt = getopt( argc, argv, "ihc:s:e:p:" ) ) != -1 ) {

	switch ( opt ) {
	case 'i':
	  create_mode = 1;
	  break;

	case 'h':
	  display_usage();
	  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	  closelog();
	  exit( EXIT_SUCCESS );
	  break;

	case 'e':
	  len = strlen( optarg );
	  if ( MAX_PATH_LENGTH < len ) {
		syslog( LOG_ERR, "ERROR: length name of event pipe is too long (255 cars max)." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  strncpy( event_pipe_name, optarg, len );
	  if ( strlen( event_pipe_name ) != len ) {
		syslog( LOG_ERR, "ERROR: an error occured when setting event pipe name." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  break;

	case 'c':
	 len = strlen( optarg );
	  if ( MAX_PATH_LENGTH <len) {
		syslog( LOG_ERR, "ERROR: length name of command pipe is too long (255 cars max)." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  strncpy( command_pipe_name, optarg, len );
	  if ( strlen( command_pipe_name ) != len ) {
		syslog( LOG_ERR, "ERROR: an error occured when setting command pipe name." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  break;

	case 's':
	 len = strlen( optarg );
	  if ( MAX_PATH_LENGTH <len) {
		syslog( LOG_ERR, "ERROR: length name of status pipe is too long (255 cars max)." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  strncpy( status_pipe_name, optarg, len );
	  if ( strlen( status_pipe_name ) != len ) {
		syslog( LOG_ERR, "ERROR: an error occured when setting status pipe name." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  break;

	case 'p':
	  /**
		  we don't use that fifo ourselves but we need its name to format
		  special messages when launchers' fifos are deleted.
	   */
	  len = strlen( optarg );
	  if ( MAX_PATH_LENGTH <len) {
		syslog( LOG_ERR, "ERROR: length name of prefix path is too long (255 cars max)." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  strncpy( prefix_name, optarg, len );
	  if ( strlen( prefix_name ) != len ) {
		syslog( LOG_ERR, "ERROR: an error occured when setting prefix path name." );
		syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
		closelog();
		exit( EXIT_FAILURE );
	  }
	  break;

	default:
	  display_usage();
	  exit(EXIT_FAILURE);
	}
  }

  if ( 0 == strlen( event_pipe_name ) ) {
	display_usage();
	syslog( LOG_ERR, "ERROR: the event pipe name has not been set." );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  if ( create_mode )
	return EXIT_SUCCESS;

  if ( 0 == strlen( command_pipe_name ) ) {
	display_usage();
	syslog( LOG_ERR, "ERROR: the command pipe name has not been set." );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  if ( 0 == strlen( status_pipe_name ) ) {
	display_usage();
	syslog( LOG_ERR, "ERROR: the status pipe name has not been set." );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  if ( 0 == strlen( prefix_name ) ) {
	display_usage();
	syslog( LOG_ERR, "ERROR: the prefix path name has not been set." );
	syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	closelog();
	exit( EXIT_FAILURE );
  }

  return EXIT_SUCCESS;
}

/** We read arguments on the command line to know what to do.
	We start by creating fifos if they don't exist yet.
	Then we open them and we initialize the inotify
	infrastructure. Once done we start the Loop.
 */
int main(int argc, char ** argv)
{

  openlog("inwatcher", LOG_PID, LOG_DAEMON);

  load_arguments(argc, argv);

  if ( make_fifo( event_pipe_name ) == EXIT_FAILURE )
	{
	  syslog( LOG_ERR, "ERROR: unable to create the event fifo." );
	  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	  closelog();
	  exit( EXIT_FAILURE ) ;
	}

  if ( create_mode )
	exit( EXIT_SUCCESS );

  event_pipe = open( event_pipe_name, O_WRONLY );
  if ( event_pipe == -1 )
	{
	  syslog( LOG_ERR, "ERROR: %m; unable to open the event pipe." );
	  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	  closelog();
	  exit( EXIT_FAILURE ) ;
	}

  command_pipe = open( command_pipe_name, O_RDONLY );
  if ( command_pipe == -1 )
	{
	  syslog( LOG_ERR, "ERROR: %m; unable to open the command pipe" );
	  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	  closelog();
	  exit( EXIT_FAILURE ) ;
	}

  status_pipe = open( status_pipe_name,  O_WRONLY );
  if ( status_pipe == -1 )
	{
	  syslog( LOG_ERR, "ERROR: %m; unable to open the status pipe" );
	  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );
	  closelog();
	  exit( EXIT_FAILURE ) ;
	}

  watch_fd = init_watches();


  if (watch_fd) {
	signal(SIGINT, destroy_watches);

	status( SUCCESS );

	syslog( LOG_INFO, "INFO: inwatcher daemon loop starting." );
	the_loop();
  }

  syslog( LOG_INFO, "INFO: inwatcher daemon terminating." );

  closelog();

  return 0;
}
