"""
Event handling system
Every "major" event in Empire (loosely defined as everything you'd want to
go into a report) is logged to the database. This file contains functions
which help manage those events - logging them, fetching them, etc.
"""

import json

from pydispatch import dispatcher

import helpers
from lib.common import db

def handle_event(signal, sender):
    """ Puts all dispatched events into the DB """
    cur = db.cursor()
    event_data = json.dumps({'signal': signal, 'sender': sender})
    log_event(cur, 'user', 'dispatched_event', event_data, helpers.get_datetime())
    cur.close()

# Record all dispatched events
dispatcher.connect(handle_event, sender=dispatcher.Any)

# Helper functions for logging common events

def agent_checkin(session_id, checkin_time):
    """
    Helper function for reporting agent checkins.

    session_id   - of an agent
    checkin_time - when that agent was first seen
    """
    cur = db.cursor()
    checkin_data = json.dumps({'checkin_time': checkin_time})
    log_event(cur, session_id, 'agent_checkin', checkin_data, helpers.get_datetime())
    cur.close()

def agent_rename(old_name, new_name):
    """
    Helper function for reporting agent name changes.

    old_name - agent's old name
    new_name - what the agent is being renamed to
    """
    # make sure to include new_name in there so it will persist if the agent
    # is renamed again - that way we can still trace the trail back if needed
    cur = db.cursor()
    name_data = json.dumps({'old_name': old_name, 'new_name': new_name})
    log_event(cur, new_name, 'agent_rename', name_data, helpers.get_datetime())
    # rename all events left over using agent's old name
    cur.execute("UPDATE reporting SET name=? WHERE name=?", [new_name, old_name])
    cur.close()

def agent_task(session_id, task_name, task_id, task):
    """
    Helper function for reporting agent taskings.

    session_id - of an agent
    task_name  - a string (e.g. "TASK_EXIT", "TASK_CMD_WAIT", "TASK_SHELL") that
                 an agent is able to interpret as a command
    task_id    - a unique ID for this task (usually an integer 0<id<65535)
    task       - the actual task definition string (e.g. for "TASK_SHELL" this
                 is the shell command to run)
    """

    cur = db.cursor()
    task_data = json.dumps({'task_name': task_name, 'task': task})
    log_event(cur, session_id, "agent_task", task_data, helpers.get_datetime(), task_id)
    cur.close()

def agent_result(cur, session_id, response_name, task_id):
    """
    Helper function for reporting agent task results.

    Note that this doesn't store the actual result data; since it comes in
    many forms (some large, and/or files, and so on) this event merely provides
    all of the details you need to fetch the actual result from the database.
    """

    response_data = json.dumps({'task_type': response_name})
    log_event(cur, session_id, "agent_result", response_data, helpers.get_datetime(), task_id)
    cur.close()

def log_event(cur, name, event_type, message, timestamp, task_id=None):
    """
    Log arbitrary events

    cur        - a database connection object (such as that returned from
                 `get_db_connection()`)
    name       - some sort of identifier for the object the event pertains to
                 (e.g. an agent or listener name)
    event_type - the category of the event - agent_result, agent_task,
                 agent_rename, etc. Ideally a succinct description of what the
                 event actually is.
    message    - the body of the event, WHICH MUST BE JSON, describing any
                 pertinent details of the event
    timestamp  - when the event occurred
    task_id    - the ID of the task this event is in relation to. Enables quick
                 queries of an agent's task and its result together.
    """
    cur.execute(
        "INSERT INTO reporting (name, event_type, message, time_stamp, taskID) VALUES (?,?,?,?,?)",
        (
            name,
            event_type,
            message,
            timestamp,
            task_id
        )
    )
