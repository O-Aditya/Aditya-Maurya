 # Scheduled Tasks Verbose Analysis Report
**Folder Name:** raw_logs
**File Types:** TXT
**Collection Date:** 2026-01-25
**Report Generated:** 2026-01-25

## 1. File Overview and Meaning
### 1.1 What Is the Scheduled Tasks Verbose Log?
The Scheduled Tasks Verbose log is a text file that records detailed information about scheduled tasks in Windows environments, including their properties, statuses, and execution history. This artifact is crucial for credential discovery, forensic analysis, and understanding system behavior.

### 1.2 Purpose and Importance
* **Credential Discovery:** The log may contain sensitive data such as the path to executable files, which could potentially reveal the location of critical system components or applications.
* **Forensic Analysis:** This artifact provides a historical record of scheduled tasks, allowing analysts to investigate system changes and identify potential malicious activities.

### 1.3 File Format and Structure
The Scheduled Tasks Verbose log is a plain text file that contains multiple lines, each representing an individual task with various properties separated by commas.

## 2. Data Types and Structure
### 2.1 Key Attributes or Fields
- TaskName
- Next Run Time
- Status
- Logon Mode
- Last Run Time
- Last Result
- Author
- Task To Run
- Start In
- Comment
- Scheduled Task State
- Idle Time
- Power Management
- Run As User
- Delete Task If Not Rescheduled
- Stop Task If Runs X Hours and X Mins
- Schedule (Scheduling data is not available in this format.)
- Schedule Type
- Start Time
- Start Date
- End Date
- Days
- Months
- Repeat

### 2.2 Field Descriptions
| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| TaskName | String | The name of the scheduled task |
| Next Run Time | DateTime | The next scheduled time for the task to run |
| Status | String | The current status of the task (e.g., Ready, Running) |
| Logon Mode | String | Whether the task runs in interactive or background mode |
| Last Run Time | DateTime | The last time the task was executed |
| Last Result | Int | The result code of the last execution (0 for success, non-zero for failure) |
| Author | String | The user who created the task (N/A if system-created) |
| Task To Run | String | The path to the executable file or command associated with the task |
| Start In | String | The directory where the task will start when executed |
| Comment | String | A brief description of the purpose of the task |
| Scheduled Task State | String | Whether the task is enabled, disabled, or not configured |
| Idle Time | String | Whether idle time is enabled for the task (Disabled by default) |
| Power Management | String | The power management settings for the task (e.g., Stop On Battery Mode) |
| Run As User | String | The user account under which the task will run (SYSTEM by default) |
| Delete Task If Not Rescheduled | String | Whether the task should be deleted if it is not rescheduled (Disabled by default) |
| Stop Task If Runs X Hours and X Mins | Time | The maximum duration a task can run before being stopped (72:00:00 by default) |
| Schedule | String | Detailed scheduling information, such as the schedule type, start time, start date, end date, days, months, repeat settings, etc. |
| Schedule Type | String | The type of schedule for the task (e.g., At logon time, Daily) |
| Start Time | DateTime | N/A in this format; used for tasks that run at specific times (e.g., 11:15:32 AM) |
| Start Date | DateTime | N/A in this format; used for tasks that run on specific dates (e.g., 25-10-2025) |
| End Date | DateTime | N/A in this format; used for tasks with an end date (e.g., the last day of a recurring task) |
| Days | String | The days of the week on which the task runs (Every 1 day(s)) |
| Months | String | The months on which the task runs (N/A