import { createRouter, createWebHistory } from 'vue-router'

import LoginView from '../views/LoginView.vue'
import RegisterView from '../views/RegisterView.vue'
import DashboardView from '../views/DashboardView.vue'

import api from '../services/api'

const routes = [

  {
    path: '/',
    redirect: '/login'
  },

  {
    path: '/login',
    component: LoginView
  },

  {
    path: '/register',
    component: RegisterView
  },

  {
    path: '/dashboard/admin',
    component: DashboardView,
    meta: {
      requiresAuth: true,
      role: 'admin'
    }
  },

  {
    path: '/dashboard/staff',
    component: DashboardView,
    meta: {
      requiresAuth: true,
      role: 'staff'
    }
  },

  {
    path: '/dashboard/trekker',
    component: DashboardView,
    meta: {
      requiresAuth: true,
      role: 'user'
    }
  }

]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Authentication and role checking
router.beforeEach(async (to) => {

  if (!to.meta.requiresAuth) {
    return true
  }

  try {

    const response = await api.get('/auth/me')

    const user = response.data.user

    if (user.role !== to.meta.role) {

      if (user.role === 'admin') {
        return '/dashboard/admin'
      }

      if (user.role === 'staff') {
        return '/dashboard/staff'
      }

      return '/dashboard/trekker'
    }

    return true

  } catch (error) {

    return '/login'

  }

})

export default router