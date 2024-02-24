import psycopg2

def fetch_from_db():
    try:
        connection = psycopg2.connect(
            user="postgres",
            password="postgres",
            host="localhost",
            port="5432",
            database="packages_production"
        )

        cursor = connection.cursor()
        # Execute the query and fetch the first 1000 results
        #The 2482 number is due to duplicates in the db the resulting set is 1000 results
        query = """select name, repository_url 
    from (
            select distinct repository_url, name, dependent_packages_count
            from packages
            where ecosystem like 'maven' and repository_url not like 'private'
            )
            as subquery
            order by dependent_packages_count desc 
            limit 100;"""

        cursor.execute(query)
        results = cursor.fetchall()
    except psycopg2.Error as e:
        print("DB Error")
        results = None
    finally:
        if connection is not None:
            cursor.close()
            connection.close()
        return(results)

def fix_gitbox_url(url):
    fixed_url = url.replace("?p=","/")
    return fixed_url
    
def get_all_urls(db_results):
    for i in range(len(db_results) - 1, -1, -1):
        name, url = db_results[i]

        if "github" in url:
            continue  # This tuple is good, move on to the next one
        elif "gitbox" in url or "gitlab" in url:
            # Store the result of fixed_gitbox_url into the second value
            db_results[i] = (name, fix_gitbox_url(url))
        else:
            # Remove the tuple from the list if it doesn't match any case
            db_results.pop(i)
    return db_results

def print_results(db_results):
    with open("dbResults.txt", 'w') as file:
        for result in db_results:
            name, url = result
            file.write(f"{url} {name}\n")

results = fetch_from_db()
results = get_all_urls(results)
print_results(results)





