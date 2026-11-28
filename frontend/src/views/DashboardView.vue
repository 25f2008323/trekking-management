<template>

  <div class="dashboard">

    <h1>Welcome, {{ user.name }}</h1>

    <h2 v-if="user.role === 'admin'">
      Admin Dashboard
    </h2>

    <h2 v-else-if="user.role === 'staff'">
      Trek Staff Dashboard
    </h2>

    <h2 v-else>
      Trekker Dashboard
    </h2>

    <p>Email: {{ user.email }}</p>
    <p>Role: {{ user.role }}</p>

    <div v-if="user.role === 'admin'" class="staff-form">

      <h3>Create Trek Staff Account</h3>

      <form @submit.prevent="createStaff">

        <input
          v-model="staffName"
          placeholder="Staff name"
          required
        />

        <input
          v-model="staffEmail"
          type="email"
          placeholder="Staff email"
          required
        />

        <input
          v-model="staffPassword"
          type="password"
          placeholder="Temporary password"
          minlength="8"
          required
        />

        <button type="submit">
          Create Staff
        </button>

      </form>

      <p>{{ staffMessage }}</p>

    </div>

    <button @click="logout">
      Logout
    </button>

  </div>

</template>

<script setup>

import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import api from '../services/api'

const router = useRouter()

const user = ref({})

const staffName = ref('')
const staffEmail = ref('')
const staffPassword = ref('')

const staffMessage = ref('')

onMounted(async () => {

  try {

    const response = await api.get('/auth/me')

    user.value = response.data.user

  } catch (error) {

    router.push('/login')

  }

})

async function createStaff() {

  try {

    const response = await api.post('/admin/staff/create', {

      name: staffName.value,
      email: staffEmail.value,
      password: staffPassword.value

    })

    staffMessage.value = response.data.message

    staffName.value = ''
    staffEmail.value = ''
    staffPassword.value = ''

  } catch (error) {

    staffMessage.value =
      error.response?.data?.message || 'Failed to create staff'

  }

}

async function logout() {

  try {

    await api.post('/auth/logout')

    router.push('/login')

  } catch (error) {

    console.error(error)

  }

}

</script>

<style scoped>

.dashboard {
  padding: 40px;
}

.staff-form {
  max-width: 400px;
  padding: 20px;
  border: 1px solid #ddd;
  margin: 30px 0;
}

input {
  display: block;
  width: 100%;
  padding: 10px;
  margin: 12px 0;
  box-sizing: border-box;
}

button {
  padding: 10px 20px;
  background: #2563eb;
  color: white;
  border: none;
  cursor: pointer;
}

</style>