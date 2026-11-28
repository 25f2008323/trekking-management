<template>
  <div class="auth-container">

    <div class="auth-card">

      <h1>Trekking Application</h1>

      <h2>Login</h2>

      <form @submit.prevent="login">

        <label>Select Role</label>

        <select v-model="role" required>
          <option value="user">Trekker</option>
          <option value="staff">Trek Staff</option>
          <option value="admin">Admin</option>
        </select>

        <div v-if="role === 'admin'">

          <label>Username</label>

          <input
            v-model="username"
            type="text"
            placeholder="Admin username"
            required
          />

        </div>

        <div v-else>

          <label>Email</label>

          <input
            v-model="email"
            type="email"
            placeholder="Enter email"
            required
          />

        </div>

        <label>Password</label>

        <input
          v-model="password"
          type="password"
          placeholder="Enter password"
          required
        />

        <button type="submit" :disabled="loading">
          {{ loading ? 'Logging in...' : 'Login' }}
        </button>

      </form>

      <p v-if="errorMessage" class="error">
        {{ errorMessage }}
      </p>

      <p v-if="role === 'user'">
        Don't have an account?
        <router-link to="/register">
          Register here
        </router-link>
      </p>

    </div>

  </div>
</template>

<script setup>

import { ref } from 'vue'
import { useRouter } from 'vue-router'
import api from '../services/api'

const router = useRouter()

const role = ref('user')
const email = ref('')
const username = ref('')
const password = ref('')

const errorMessage = ref('')
const loading = ref(false)

async function login() {

  errorMessage.value = ''
  loading.value = true

  try {

    const response = await api.post('/auth/login', {

      role: role.value,

      email: email.value,
      username: username.value,

      password: password.value

    })

    await router.push(response.data.redirect)

  } catch (error) {

    errorMessage.value =
      error.response?.data?.message || 'Login failed'

  } finally {

    loading.value = false

  }

}

</script>

<style scoped>

.auth-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 100vh;
  background: #eef2f7;
}

.auth-card {
  width: 350px;
  padding: 30px;
  background: white;
  border-radius: 12px;
  box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

h1, h2 {
  text-align: center;
}

input, select {
  display: block;
  width: 100%;
  padding: 10px;
  margin: 10px 0 18px;
  box-sizing: border-box;
}

button {
  width: 100%;
  padding: 12px;
  background: #2563eb;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
}

.error {
  color: red;
}

</style>