## 2.2.0 ##
[NEW] - Admin > Statuses & issue codes: add, rename, reorder, colour, deactivate or delete (only when unused).
        Statuses can be marked "counts as done" (excluded from overdue, hidden by "Hide done"). Renaming an issue code updates all initiatives.
        Lists are stored in the database (tables statuses, issue_codes) and seeded from the previous fixed values.
[CHANGE] - Dashboard tiles follow the status list; table view fits the screen without horizontal scrolling.
[CHANGE] - Removed the subtitle on the main page and the "What" heading in the initiative form.

## 2.1.0 ##
[NEW] - Updates timeline: responsible people and admins post dated updates (optionally changing status); authors/admins can delete them.
        The former single "Comments / Status" text is imported once as the first update of each initiative.
[NEW] - Impact metrics defined by admins (Admin > Impact metrics): single value or before/after, unit, help text, optional total on dashboard.
        Defaults created on first start: Hours saved / month, Tickets reduced / month, CSAT.
[NEW] - Responsible picker: tick one or more people with an account, or "Owner not on the list" for free-text names.
        People listed as responsible may edit and post updates (in addition to admins and the last editor).
[NEW] - Priority (1 Critical ... 5 Very low) shown, editable, sortable; users have a Full name (admin editable).
[NEW] - Excel export includes priority, impact metrics and a second "Updates" sheet.
[CHANGE] - Dates like "June 2025", "05-2025", "June 10, 2025", "4-23-2025" are understood; ambiguous ones (04/05/2025) are shown as typed.
[CHANGE] - List hides completed initiatives by default (toggle remembered).
[MIGRATION] - Runs automatically on start and only ADDS tables/columns (users.full_name, initiatives.priority if missing,
        initiative_updates, initiative_metrics, metric_definitions, app_meta). Back up data/database.db before deploying.

## 2.0.0 ##
[NEW] - Dashboard with KPI tiles (New / In progress / On hold / Completed / Overdue) that work as quick filters
[NEW] - Card and table views (choice remembered), global search (shortcut "/"), filters by issue code and owner, sorting, "Hide completed"
[NEW] - Initiative detail page: key facts, timeline progress bar, description and status in full
[NEW] - Change history per initiative (who changed what and when) - table initiative_history is created automatically on start
[NEW] - Overdue / due-soon indicators computed from ETA
[NEW] - "On hold" status, date pickers, one shared form for new/edit, unsaved-changes warning
[NEW] - Excel export with readable columns, autofilter and frozen header
[CHANGE] - New professional look (Inter font, consistent components, toast notifications), all UI in English
[CHANGE] - User activate/admin/delete actions use POST instead of GET links; inactive users can no longer sign in
[FIX] - Inconsistent issue codes ("SD tool review" vs "SD Tool Review"), 404 page instead of a crash for a missing initiative
[CONFIG] - SECRET_KEY and DB_FILE can be set via environment variables

Run: python -m venv .venv ; .venv\Scripts\pip install -r requirements.txt ; .venv\Scripts\python app.py

## 1.0.1 ##
New package used: Pandas, XlsxWriter, openpyxl

[CHANGE] - Edited priviliges to edit initiatives. Only Admin or last last editor (owner) can edit
[CHANGE] - Flash message dissapear after short while
