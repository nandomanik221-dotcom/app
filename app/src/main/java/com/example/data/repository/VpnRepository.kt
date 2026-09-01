package com.example.data.repository

import com.example.data.local.dao.VpnProfileDao
import com.example.data.local.entity.VpnProfileEntity
import com.example.model.VpnProfile
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

class VpnRepository(private val dao: VpnProfileDao) {

    val allProfiles: Flow<List<VpnProfile>> = dao.getAllProfiles().map { entities ->
        entities.map { it.toDomain() }
    }

    suspend fun getProfileById(id: Long): VpnProfile? {
        return dao.getProfileById(id)?.toDomain()
    }

    suspend fun insert(profile: VpnProfile): Long {
        return dao.insertProfile(VpnProfileEntity.fromDomain(profile))
    }

    suspend fun insertAll(profiles: List<VpnProfile>) {
        dao.insertProfiles(profiles.map { VpnProfileEntity.fromDomain(it) })
    }

    suspend fun update(profile: VpnProfile) {
        dao.updateProfile(VpnProfileEntity.fromDomain(profile))
    }

    suspend fun delete(profile: VpnProfile) {
        dao.deleteProfile(VpnProfileEntity.fromDomain(profile))
    }

    suspend fun deleteById(id: Long) {
        dao.deleteProfileById(id)
    }

    suspend fun updatePing(id: Long, pingMs: Int) {
        dao.updatePing(id, pingMs)
    }

    suspend fun toggleFavorite(id: Long, isFavorite: Boolean) {
        dao.updateFavorite(id, isFavorite)
    }

    suspend fun checkSeedNeeded() {
        if (dao.getProfileCount() == 0) {
            // Seed defaults
        }
    }
}
