from apscheduler.schedulers.background import BackgroundScheduler

# -------------------------------
# Auto-Delete Old Messages Job
# -------------------------------
def delete_old_messages():
    with app.app_context():
        one_week_ago = datetime.utcnow() - timedelta(weeks=1)
        old_messages = Message.query.filter(Message.timestamp < one_week_ago).all()
        for msg in old_messages:
            db.session.delete(msg)
        db.session.commit()
        print(f"Deleted {len(old_messages)} messages older than one week.")

# Initialize APScheduler to run the delete job once every day.
scheduler = BackgroundScheduler()
scheduler.add_job(func=delete_old_messages, trigger="interval", days=1)
scheduler.start()