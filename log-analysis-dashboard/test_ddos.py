from locust import HttpUser, task, between

class LoadTest(HttpUser):
    wait_time = between(0.1, 0.5)

    @task
    def attack(self):
        self.client.get("/")
