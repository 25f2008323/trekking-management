<template>

  <div class="auth-container">

    <div class="auth-card">

      <h2>Trekker Registration</h2>

      <form @submit.prevent="register">

        <label>Name</label>

        <input
          v-model="name"
          type="text"
          required
          placeholder="Enter your name"
        />

        <label>Email</label>

        <input
          v-model="email"
          type="email"
          required
          placeholder="Enter your email"
        />

        <label>Password</label>

        <input
          v-model="password"
          type="password"
          required
          minlength="8"
          placeholder="Create password"
        />

        <button type="submit" :disabled="loading">
          {{ loading ? 'Registering...' : 'Register' }}
        </button>

      </form>

      <p v-if="message">{{ message }}</p>

      <p v-if="errorMessage" style="color:red">
        {{ errorMessage }}
      </p>

      <router-link to="/login">
        Back to Login
      </router-link>

    </div>

  </div>

</template>

<script setup>

import { ref } from 'vue'
import { useRouter } from 'vue-router'
import api from '../services/api'

const router = useRouter()

const name = ref('')
const email = ref('')
const password = ref('')

const message = ref('')
const errorMessage = ref('')
const loading = ref(false)

async function register() {

  loading.value = true
  message.value = ''
  errorMessage.value = ''

  try {

    const response = await api.post('/auth/register', {

      name: name.value,
      email: email.value,
      password: password.value

    })

    message.value = response.data.message

    setTimeout(() => {
      router.push('/login')
    }, 1000)

  } catch (error) {

    errorMessage.value =
      error.response?.data?.message || 'Registration failed'

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
}

input {
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
  cursor: pointer;
}

</style>